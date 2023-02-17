#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/poll.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/msg.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/mman.h>           // Mmap system call
#include <sys/ioctl.h>          // IOCTL system call
#include <getopt.h>             // Option parsing

#include "ucas_log.h"
#include "version.h"
#include "tcp_udp_lib.h"
#include "pthread_own.h"
#include "file_trans_and_rcv.h"
#include "axidma_ioctl.h"
#include "conversion.h"
#include "libaxidma.h"
#include "util.h"

#define DEFAULT_TRANSFER_SIZE       1500

#define MAX_LINK_NUM 1
#define LOG_TAG "axidma-net.c: "

static int server_fd = -1, client_nfp = -1;
static file_size_type rcv_len = 0;

static pthread_t rcv_file_thread = -1;
static pthread_t snd_file_thread = -1;
static pthread_t monitor_thread = -1;

extern axidma_dev_t axidma_dev;   
int tx_channel, rx_channel;
const array_t *tx_chans, *rx_chans;
char *tx_buf, *rx_buf;
int phy_addr = 0x43c00000;
volatile unsigned int *vir_addr = NULL;
int dst_port_num1 = 8000;
int dst_port_num2 = 8001;
char *dst_ipaddr1 = "192.168.1.123";
char *dst_ipaddr2 = "192.168.1.124";

unsigned int sync_data_send(int sync_port_num, int reg_offset, unsigned int value);
int mmap_init(void);

unsigned int sync_data_send(int sync_port_num, int reg_offset, unsigned int value)
{
    unsigned int read_result = 0;
    volatile unsigned int *sync_vir_addr = NULL;
    switch (sync_port_num)
    {
        default:
            LOGD(LOG_TAG"Wrong send sync_port_num.\n");
            break;
        case 0:
            sync_vir_addr = vir_addr + reg_offset / 4;
            LOGD(LOG_TAG"Write 32-bits value 0x%08x to 0x%08x (0x%p)\n",
                 value, (phy_addr + sync_port_num * 0x1000 + reg_offset),
                 sync_vir_addr);
            *sync_vir_addr = value;
            break;
    }

    return 0;
}

int mmap_init(void)
{
    int n, fd;

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1)
    {
        LOGE(LOG_TAG"Open /dev/mem error\r\n");
        return -1;
    }

    vir_addr = mmap(NULL, 64, PROT_READ | PROT_WRITE, MAP_SHARED, fd, phy_addr);
    if (vir_addr == NULL)
    {
        LOGD(LOG_TAG"vir_addr NULL pointer!\n");
    }
    LOGD(LOG_TAG"vir_addr 0x%08X Memory mapped at address %p.\n", phy_addr, vir_addr);

    fflush(stdout);

    return 0;
}

static int open_or_create_file(const char *file_path, int clean_file)
{
    int fd = -1, ret_val = -1;
    fd = open(file_path, O_RDWR | O_CREAT | O_LARGEFILE);
    if (fd < 0)
    {
        LOGE(LOG_TAG"open failed for file:%s,errno = %d\r\n", file_path, errno);
        return -errno;
    }

    if (clean_file)
    {
        ret_val = ftruncate(fd, 0);
        if (ret_val < 0)
        {
            LOGE(LOG_TAG"ftruncate failed for file:%s,errno = %d\r\n", file_path, errno);
            return -errno;
        }
    }

    return fd;
}

void *monitor_func(void *arg)
{
    int delay_s = 2;
    while (1)
    {
        sleep(delay_s);
    }
}

int axidma_prep(void)
{
    int rc, len, data;

    // mmap_init();
    // sync_data_send(0, 0, 0x0);
    // Initialize the AXI DMA device
    axidma_dev = axidma_init();
    if (axidma_dev == NULL)
    {
        fprintf(stderr, "Failed to initialize the AXI DMA device.\n");
        rc = 1;
        goto ret_axidma;
    }
    // Map memory regions for the transmit and receive buffers
    tx_buf = axidma_malloc(axidma_dev, 2048);
    if (tx_buf == NULL)
    {
        perror("Unable to allocate transmit buffer from the AXI DMA device.");
        rc = -1;
        goto ret_axidma;
    }
    rx_buf = axidma_malloc(axidma_dev, 4096);
    if (rx_buf == NULL)
    {
        perror("Unable to allocate receive buffer from the AXI DMA device");
        rc = -1;
        goto ret_axidma;
    }
    // Get all the transmit and receive channels

    tx_chans = axidma_get_dma_tx(axidma_dev);
    rx_chans = axidma_get_dma_rx(axidma_dev);


    if (tx_chans->len < 1)
    {
        fprintf(stderr, "Error: No transmit channels were found.\n");
        rc = -ENODEV;
        goto ret_axidma;
    }
    if (rx_chans->len < 1)
    {
        fprintf(stderr, "Error: No receive channels were found.\n");
        rc = -ENODEV;
        goto ret_axidma;
    }


    /* If the user didn't specify the channels, we assume that the transmit and
     * receive channels are the lowest numbered ones. */
    if (tx_channel == -1 && rx_channel == -1)
    {
        tx_channel = tx_chans->data[0];
        rx_channel = rx_chans->data[0];
    }

    tx_channel = 0;
    rx_channel = 1;

    printf("Using transmit channel %d and receive channel %d.\n", tx_channel, rx_channel);

    return 0;
ret_axidma:
    if (rx_buf != NULL)
    {
        axidma_free(axidma_dev, rx_buf, DEFAULT_TRANSFER_SIZE);
        rx_buf = NULL;
    }

    if (tx_buf != NULL)
    {
        axidma_free(axidma_dev, tx_buf, DEFAULT_TRANSFER_SIZE);
        tx_buf = NULL;
    }
    if (axidma_dev != NULL)
    {
        axidma_destroy(axidma_dev);
        axidma_dev = NULL;
    }
    return -1;
}

/*
* get data from ethernet interface and send them to FPGA by axidma.
*/
static void *rcv_file_func(void *arg)
{
    int ret_val = -1;
    int *tmp_fd = (int *)arg;
    file_info rcv_file_info;
    int axidma_fd = 0;
    int rc, i;
    struct sockaddr_in recv_addr;
    socklen_t addrlen = sizeof(recv_addr);


    // *(tx_buf + 0) = 0x1c;
    // *(tx_buf + 1) = 0x15;
    // *(tx_buf + 2) = 0xb5;
    // *(tx_buf + 3) = 0xb5;

    // for(i = 4; i < 128; i++)
    // {
    //     *(tx_buf + i) = i;
    // }

    printf("file fd = %d\r\n", *tmp_fd);

    while(1)
    {
        ret_val = recvfrom(*tmp_fd, tx_buf, DEFAULT_TRANSFER_SIZE, 0,(struct sockaddr*)&recv_addr,&addrlen);
        printf("[recv from %s:%d]%s \n",inet_ntoa(*(struct in_addr*)&recv_addr.sin_addr.s_addr),ntohs(recv_addr.sin_port),tx_buf);
        if (ret_val < 0)
        {
            LOGE("get net_data faild,errno = %d\r\n", errno);
            return -errno;
        }

        printf("get data form eth:\n");
        for(i = 0; i < 30; i++)
        {
            printf("0x%02x ", tx_buf[i]);
        }
        printf("\n");
        if(ntohs(recv_addr.sin_port) == 9527)
        {
            if(strncmp(tx_buf, "cmd_start", 9) == 0)
            {
                sync_data_send(0, 0x0, 0x1);
            }
            if(strncmp(tx_buf, "send_big", 8) == 0)
            {
                sync_data_send(0, 0x4, 0x1);
            }
            if(strncmp(tx_buf, "receive_big", 11) == 0)
            {
                sync_data_send(0, 0x8, 0x1);
            }
        }
        else
        {
            rc = axidma_oneway_transfer(axidma_dev, tx_channel, tx_buf, DEFAULT_TRANSFER_SIZE, true);
            if (rc < 0)
            {
                LOGD("axidma_oneway_transfer:%d,errno = %d\r\n", rc, errno);
                break;
            } 
        }
    }


    // ret_val = file_rcv(&rcv_file_info, &rcv_len, STROE_AFTER_RCV_DONE, *tmp_fd);
    // if (ret_val < 0)
    // {
    //     LOGE("file_rcv gose wrong,ret_val = %d\r\n", ret_val);
    // }
    // else
    // {
    //     sync_data_send(0, 0, 0x1);
    //     usleep(100000);
    //     sync_data_send(0, 0, 0x3);
    //     usleep(100000);
    //     LOGD("rcv file done\r\n");
    //     axidma_fd = open_or_create_file(rcv_file_info.file_name, 0);
    //     if (axidma_fd < 0)
    //     {
    //         LOGE(LOG_TAG"axidma_fd open failed for file:%s,errno = %d\r\n", rcv_file_info.file_name, errno);
    //     }
    //     do
    //     {
    //         memset(tx_buf, 0x0, DEFAULT_TRANSFER_SIZE);
    //         ret_val = read(axidma_fd, tx_buf, DEFAULT_TRANSFER_SIZE);
    //         // printf("Snd axi data to fpga:\n");
    //         // for(ii = 0; ii < DEFAULT_TRANSFER_SIZE; ii++)
    //         // {
    //         //     printf("0x%02X ", *(tx_buf + ii));
    //         // }
    //         // printf("\n");

    //         if (ret_val <= 0)
    //         {
    //             LOGE(LOG_TAG"read file finished!\r\n");
    //             break;
    //         }
    //         rc = axidma_oneway_transfer(axidma_dev, tx_channel, tx_buf, DEFAULT_TRANSFER_SIZE, true);
    //         if (rc < 0)
    //         {
    //             LOGD("axidma_oneway_transfer:%d,errno = %d\r\n", rc, errno);
    //             break;
    //         }
    //     }
    //     while (ret_val > 0);
	// usleep(100000);
	// sync_data_send(0, 0, 0x0);
    // }
}

/*
* get data from FPGA and then send them to eth.
*/
static void *snd_file_func(void *arg)
{
    int ret_val = -1;
    int *tmp_fd = (int *)arg;
    int rc, i;


    while(1)
    {

        rc = axidma_oneway_transfer(axidma_dev, rx_channel, rx_buf, DEFAULT_TRANSFER_SIZE, true);
        if (rc < 0)
        {
            LOGD("axidma_oneway_transfer:%d,errno = %d\r\n", rc, errno);
            break;
        }

        printf("axidma received %d bytes data:\n");
        for(i = 0; i < 30; i++)
        {
            printf("0x%02x ", rx_buf[i]);
        }
        printf("\n");


        struct sockaddr_in sock_addr = {0};	
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_port = htons(dst_port_num1);
        sock_addr.sin_addr.s_addr = inet_addr(dst_ipaddr1);


        ret_val = sendto(*tmp_fd, rx_buf, DEFAULT_TRANSFER_SIZE, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
        if (rc < 0)
        {
            LOGD("client_nfp:%d,errno = %d\r\n", ret_val, errno);
            break;
        }

    }
}

static void sigfunc(int sig)
{
    LOG("recv a sig = %d,do clean flow!\r\n", sig);
    if (rx_buf != NULL)
    {
        axidma_free(axidma_dev, rx_buf, DEFAULT_TRANSFER_SIZE);
        rx_buf = NULL;
    }

    if (tx_buf != NULL)
    {
        axidma_free(axidma_dev, tx_buf, DEFAULT_TRANSFER_SIZE);
        tx_buf = NULL;
    }
    if (axidma_dev != NULL)
    {
        axidma_destroy(axidma_dev);
        axidma_dev = NULL;
    }
    if (rcv_file_thread > 0)
    {
        //pthread_join(rcv_file_thread);
        pthread_cancel(rcv_file_thread);
        rcv_file_thread = -1;
    }

    if (monitor_thread > 0)
    {
        //pthread_join(monitor_thread);
        pthread_cancel(monitor_thread);
        monitor_thread = -1;
    }
    LOG("terminal the programme!\r\n");

    if (client_nfp > 0)
    {
        close(client_nfp);
        client_nfp = -1;
    }

    if (server_fd > 0)
    {
        close(server_fd);
        server_fd = -1;
    }

    exit(1);
}

int main(int argc, char **argv)
{
    int ret_val = -1, i = 0;
    int input_c = 0;
    struct sockaddr_in c_add;
    unsigned int portnum = 9009;

    // sig_t sighandler;

    // sighandler = (SIGINT, sigfunc);
    // RETURN_ERR(LOG_TAG, "signal  SIGINT", sighandler == SIG_ERR);

    // sighandler = signal(SIGTERM, sigfunc);
    // RETURN_ERR(LOG_TAG, "signal  SIGTERM", sighandler == SIG_ERR);

    // if (argc < 2)
    // {
    //     LOG("usage: %s file_name port_number\r\n", argv[0]);
    //     LOG("default port number is %d\r\n", portnum);
    //     LOG("print \'c\' continue...\r\n");
    //     if (getchar() == 'c')
    //         LOG("continue...\r\n");
    //     else
    //         return 0;
    // }

    show_version();

    LOGD(LOG_TAG"lg tp 1...\r\n");

    // if (axidma_prep() < 0)
    // {
    //     LOGE(LOG_TAG"axidma_prep failed,errno = %d\r\n", errno);
    //     return -errno;
    // }
   
    server_fd = tcp_udp_server_init(1, portnum, MAX_LINK_NUM);
    if (server_fd < 0)
    {
        LOGE(LOG_TAG"udp socket failed,errno = %d\r\n", errno);
        return -errno;
    }
    LOGD(LOG_TAG"server_fd = %d\r\n", server_fd);

    ret_val = pthread_create_and_setaffinity(&rcv_file_thread, NULL, rcv_file_func, (void *)(&server_fd), -1);
    if (ret_val != 0)
    {
        LOGE(LOG_TAG"pthread_create_and_setaffinity faild for rcv_file_func!\r\n");
    }

    ret_val = pthread_create_and_setaffinity(&snd_file_thread, NULL, snd_file_func, (void *)(&server_fd), -1);
    if (ret_val != 0)
    {
        LOGE(LOG_TAG"pthread_create_and_setaffinity faild for snd_file_func!\r\n");
    }
    while(1)
    {
        sleep(2);
    }


    if (rcv_file_thread > 0)
    {
        LOGD("wait for rcv_file_func thread done...\r\n");
        pthread_join(rcv_file_thread, NULL);
        LOGD("rcv_file_func thread done!\r\n");
        rcv_file_thread = -1;
    }

    if (rx_buf != NULL)
    {
        axidma_free(axidma_dev, rx_buf, DEFAULT_TRANSFER_SIZE);
        rx_buf = NULL;
    }

    if (tx_buf != NULL)
    {
        axidma_free(axidma_dev, tx_buf, DEFAULT_TRANSFER_SIZE);
        tx_buf = NULL;
    }
    if (axidma_dev != NULL)
    {
        axidma_destroy(axidma_dev);
        axidma_dev = NULL;
    }

    if (rcv_file_thread > 0)
    {
        //pthread_join(rcv_file_thread, NULL);
        pthread_cancel(rcv_file_thread);
        rcv_file_thread = -1;
    }

    if (monitor_thread > 0)
    {
        //pthread_join(monitor_thread, NULL);
        pthread_cancel(monitor_thread);
        monitor_thread = -1;
    }

    if (client_nfp > 0)
    {
        close(client_nfp);
        client_nfp = -1;
    }

    if (server_fd > 0)
    {
        close(server_fd);
        server_fd = -1;
    }

    return 0;
}
