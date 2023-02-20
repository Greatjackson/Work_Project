#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include "ucas_log.h"

#define TCP_TYPE 0
#define LINKS_LIMIT 10
#define RETRY_TIMES 7
#define LOG_TAG "tcp_udp_lib.c  :"

int tcp_udp_server_init(int type, int portnum, int max_num_of_links) // 0 for tcp,1 for udp
{
    int ret_val = -1;
    int server_fd = -1;
    struct sockaddr_in s_add;

    printf("portnum : %d\r\n", portnum);

    server_fd = socket(type == TCP_TYPE ? AF_INET : PF_INET, type == TCP_TYPE ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (server_fd < 0)
    {
        LOGE(LOG_TAG "%s socket failed,errno = %d\r\n", type == TCP_TYPE ? "tcp" : "udp", errno);
        return -errno;
    }

    bzero(&s_add, sizeof(struct sockaddr_in));
    s_add.sin_family = (type == TCP_TYPE ? AF_INET : PF_INET);
    s_add.sin_addr.s_addr = htonl(INADDR_ANY);
    s_add.sin_port = htons(portnum);

    printf("address: %s\r\n", inet_ntoa(s_add.sin_addr));

    ret_val = bind(server_fd, (struct sockaddr *)(&s_add), sizeof(struct sockaddr));
    if (ret_val < 0)
    {
        LOGE(LOG_TAG "%s bind failed,errno = %d!\r\n", type == TCP_TYPE ? "tcp" : "udp", errno);
        return -errno;
    }

    if (type == TCP_TYPE)
    {
        if (max_num_of_links < LINKS_LIMIT)
            max_num_of_links = LINKS_LIMIT;
        ret_val = listen(server_fd, max_num_of_links);
        if (ret_val < 0)
        {
            LOGE(LOG_TAG "tcp listen failed,errno = %d!\r\n", errno);
            return -errno;
        }
    }

    return server_fd;
}

int tcp_udp_client_init(int type, int portnum, int client_portnum, const char *server_ip, unsigned int retry_times) // 0 for tcp,1 for udp
{
    int ret_val = -1;
    int fd = -1, i = 0;
    unsigned int retry_count = 0;
    struct sockaddr_in s_add, client_addr;

    fd = socket(type == TCP_TYPE ? AF_INET : PF_INET, type == TCP_TYPE ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0)
    {
        LOGE(LOG_TAG "%s socket failed,errno = %d\r\n", type == TCP_TYPE ? "tcp" : "udp", errno);
        return -errno;
    }

    bzero(&client_addr, sizeof(struct sockaddr_in));
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(client_portnum);
    // memset(&(client_addr.sin_zero), 0, sizeof(client_addr.sin_zero));

    if (bind(fd, (struct sockaddr *)&client_addr, sizeof(struct sockaddr)) == -1)
    {
        LOGE(LOG_TAG "%s bind failed,errno = %d\r\n", type == TCP_TYPE ? "tcp" : "udp", errno);
        return -errno;
    }

    bzero(&s_add, sizeof(struct sockaddr_in));
    s_add.sin_family = (type == TCP_TYPE ? AF_INET : PF_INET);
    s_add.sin_addr.s_addr = inet_addr(server_ip);
    s_add.sin_port = htons(portnum);

    if (type == TCP_TYPE)
    {
        retry_count = 0;
    connect_retry:
        ret_val = connect(fd, (struct sockaddr *)(&s_add), sizeof(struct sockaddr));
        if (ret_val < 0)
        {
            LOGE(LOG_TAG "tcp connect failed,errno = %d,retry!\r\n", errno);
            if (retry_count++ <= retry_times)
            {
                usleep(5000000);
                goto connect_retry;
            }
            LOGE(LOG_TAG "tcp connect failed,errno = %d,retry timeout,exit!\r\n", errno);
            return -errno;
        }
    }

    return fd;
}

int tcp_udp_accept(int type, int socket_fd, struct sockaddr *deliver)
{
    int ret_val = -1;
    int sin_size = sizeof(struct sockaddr);
    struct sockaddr c_add;

    ret_val = accept(socket_fd, (struct sockaddr *)(deliver ? deliver : &c_add), &sin_size);
    if (ret_val < 0)
    {
        LOGE(LOG_TAG "accept failed,errno = %d!\r\n", errno);
        return -errno;
    }

    return ret_val;
}
#if 1
int tcp_udp_read(int type, int fd, char *buffer, size_t len, int (*filter)(void *inner_arg, void *outer_arg), void *arg)
{
    int ret_val = -1, read_len = 0, retry_count = 0;
net_read_retry:
    ret_val = read(fd, buffer + read_len, len - read_len);
    if (ret_val < 0)
    {
        LOGE("get net_data faild,errno = %d\r\n", errno);
        return -errno;
    }
    else
    {
        if (filter)
        {
            if (filter((void *)(buffer + read_len), arg))
            {
                read_len += ret_val;
            }
        }
        else
        {
            read_len += ret_val;
        }

        if (read_len < len)
        {
            if (retry_count++ < 10)
                goto net_read_retry;
        }
    }

    return read_len;
}

int tcp_udp_write(int type, int fd, char *buffer, size_t len)
{
    int ret_val = -1, write_len = 0, retry_count = 0;
net_write_retry:
    ret_val = write(fd, buffer + write_len, len - write_len);
    if (ret_val < 0)
    {
        LOGE("snd net_data faild,errno = %d\r\n", errno);
        return -errno;
    }
    else if ((write_len += ret_val, write_len < len))
    {
        if (retry_count++ < 10)
            goto net_write_retry;
    }

    return write_len;
}
#endif