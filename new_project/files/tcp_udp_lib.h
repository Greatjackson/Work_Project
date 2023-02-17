#ifndef TCP_UDP_LIB_H
#define TCP_UDP_LIB_H
#include <sys/socket.h>
#include <netinet/in.h>

extern int tcp_udp_server_init(int type, int portnum, int max_num_of_links);   // 0 for tcp,1 for udp
extern int tcp_udp_client_init(int type, int portnum, const char *server_ip, unsigned int retry_times); // 0 for tcp,1 for udp
extern int tcp_udp_accept(int type, int socket_fd, struct sockaddr *deliver);
extern int tcp_udp_write(int type, int fd, char *buffer, size_t len);
extern int tcp_udp_read(int type, int fd, char *buffer, size_t len, int (*filter)(void *inner_arg, void *outer_arg), void *arg);
#endif