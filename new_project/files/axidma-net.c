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

static int server_fd = -1, client_nfp = -1, cmd_fd = -1;
static file_size_type rcv_len = 0;

static pthread_t rcv_cmd_thread = -1;
static pthread_t rcv_file_thread = -1;
static pthread_t snd_file_thread = -1;
static pthread_t monitor_thread = -1;

extern axidma_dev_t axidma_dev;   
int tx_channel, rx_channel;
const array_t *tx_chans, *rx_chans;
char *tx_buf, *rx_buf;
int phy_addr = 0x43c00000;
volatile unsigned int *vir_addr = NULL;

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

static int cmd_analysis(char *buf)
{
    unsigned int code_value, flag;
    char code_value_buf[16] = {0};
    char flag_buf[4] = {0};

    if(strncmp(buf, "cmd_start", 9) == 0)
    {
        sync_data_send(0, 0x0, 0x1);
    }
    else if(strncmp(buf, "cmd_end", 7) == 0)
    {
        sync_data_send(0, 0x0, 0x0);
    }

    else if(strncmp(buf, "send_big", 8) == 0)
    {
        sync_data_send(0, 0x4, 0x1);
    }
    else if(strncmp(buf, "send_little", 11) == 0)
    {
        sync_data_send(0, 0x4, 0x0);
    }

    else if(strncmp(buf, "receive_big", 11) == 0)
    {
        sync_data_send(0, 0x8, 0x1);
    }
    else if(strncmp(buf, "receive_little", 14) == 0)
    {
        sync_data_send(0, 0x8, 0x0);
    }

    else if(strncmp(buf, "space_code", 10) == 0)
    {
        memcpy(code_value_buf, buf+11, 8); 
        printf("str: %s\n", code_value_buf);
        sscanf(code_value_buf, "%x", &code_value);
        sync_data_send(0, 0xC, code_value);
        memcpy(flag_buf, buf+20, 1);
        flag = atoi(flag_buf);        
        sync_data_send(0, 0x10, flag);
    }
    else if(strncmp(buf, "begin_code", 10) == 0)
    {
        memcpy(code_value_buf, buf+11, 8); 
        printf("str: %s\n", code_value_buf);
        sscanf(code_value_buf, "%x", &code_value);
        sync_data_send(0, 0x14, code_value);
        memcpy(flag_buf, buf+20, 1);
        flag = atoi(flag_buf);                 
        sync_data_send(0, 0x18, flag);
    }

    else
    {
        LOGE("invalid command, please check again!\r\n", errno);
        return -1;
    }
    
    return 0;
}

/*
* get command data from ethernet interface .
*/
static void *rcv_cmd_func(void *arg)
{
    int ret_val = -1;
    int *tmp_fd = (int *)arg;   
    int i;
    char cmd_buf[64] = {0};

    printf("cmd fd = %d\r\n", *tmp_fd);

    while(1)
    {
        ret_val = read(*tmp_fd, cmd_buf, 64);
        if (ret_val < 0)
        {
            LOGE(LOG_TAG"get net_data faild,errno = %d\r\n", errno);
            return -errno;
        }

        printf("get cmd data form eth:\n");
        for(i = 0; i < 30; i++)
        {
            printf("0x%02x ", cmd_buf[i]);
        }
        printf("\n");

        ret_val = cmd_analysis(cmd_buf);
        if (ret_val < 0)
        {
            LOGE("get net_data faild,errno = %d\r\n", errno);
            return -errno;
        }

    }
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
    char code_value_buf = {0};
    char flag_buf = {0};
    unsigned int code_value, flag;

    printf("file fd = %d\r\n", *tmp_fd);

    while(1)
    {
        ret_val = read(*tmp_fd, tx_buf, DEFAULT_TRANSFER_SIZE);
        if (ret_val < 0)
        {
            LOGE(LOG_TAG"get net_data faild,errno = %d\r\n", errno);
            return -errno;
        }

        printf("get data form eth:\n");
        for(i = 0; i < 30; i++)
        {
            printf("0x%02x ", tx_buf[i]);
        }
        printf("\n");

        rc = axidma_oneway_transfer(axidma_dev, tx_channel, tx_buf, DEFAULT_TRANSFER_SIZE, true);
        if (rc < 0)
        {
            LOGD("axidma_oneway_transfer:%d,errno = %d\r\n", rc, errno);
            break;
        } 
    }
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
            LOGE(LOG_TAG"axidma_oneway_transfer:%d,errno = %d\r\n", rc, errno);
            break;
        }

        printf("axidma received data:\n");
        for(i = 0; i < 30; i++)
        {
            printf("0x%02x ", rx_buf[i]);
        }
        printf("\n");

        ret_val = write(*tmp_fd, rx_buf, DEFAULT_TRANSFER_SIZE);
        if (rc < 0)
        {
            LOGD("write data:%d,errno = %d\r\n", ret_val, errno);
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
    if (rcv_cmd_thread > 0)
    {
        //pthread_join(rcv_cmd_thread);
        pthread_cancel(rcv_cmd_thread);
        rcv_cmd_thread = -1;
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

    if (cmd_fd > 0)
    {
        close(cmd_fd);
        cmd_fd = -1;
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

    show_version();

    LOGD(LOG_TAG"lg tp 1...\r\n");

    if (axidma_prep() < 0)
    {
        LOGE(LOG_TAG"axidma_prep failed,errno = %d\r\n", errno);
        return -errno;
    }
   
    mmap_init();

    cmd_fd = tcp_udp_client_init(0, 9009, 9527, "192.168.1.105", 10);
    if (cmd_fd < 0)
    {
        LOGE(LOG_TAG"tcp socket failed,errno = %d\r\n", errno);
        return -errno;
    }
    LOGD(LOG_TAG"cmd_fd = %d\r\n", cmd_fd);

    ret_val = pthread_create_and_setaffinity(&rcv_cmd_thread, NULL, rcv_cmd_func, (void *)(&cmd_fd), -1);
    if (ret_val != 0)
    {
        LOGE(LOG_TAG"pthread_create_and_setaffinity faild for rcv_cmd_func!\r\n");
    }

    server_fd = tcp_udp_client_init(0, 9009, 1234, "192.168.1.105", 10);
    if (server_fd < 0)
    {
        LOGE(LOG_TAG"tcp socket failed,errno = %d\r\n", errno);
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
    if (rcv_cmd_thread > 0)
    {
        //pthread_join(rcv_cmd_thread, NULL);
        pthread_cancel(rcv_cmd_thread);
        rcv_cmd_thread = -1;
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
    if (cmd_fd > 0)
    {
        close(cmd_fd);
        cmd_fd = -1;
    }

    return 0;
}
