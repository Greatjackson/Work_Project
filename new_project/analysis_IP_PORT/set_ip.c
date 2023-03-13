#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>


#include <sys/stat.h>
#include <sys/types.h>


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>



#include <linux/route.h>
#include <linux/if_arp.h>



unsigned char server_ip[32];
unsigned char client_ip[32];
unsigned char client_mask[32];
unsigned char client_mac[6];
unsigned int server_port_num;
unsigned int client_port_num;
unsigned int cmd_port_num;


int net_eth_set_mac(char *eth_name, unsigned char *mac)
{
	int ret;
	int fd;
	short flag;
	struct ifreq ifreq;
 
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
 
	memset(&ifreq, 0x00, sizeof(struct ifreq));
	strcpy(ifreq.ifr_name, eth_name);
 
	ret = ioctl(fd, SIOCGIFFLAGS, &ifreq);
 
	if (ret < 0) {
		ret = -1;
		perror("SIOCGIFFLAGS: ");
		goto ERROR;
	}
 
	flag = ifreq.ifr_flags;
 
	if (flag & IFF_UP) {
		ifreq.ifr_flags &= ~IFF_UP;
		ioctl(fd, SIOCSIFFLAGS, &ifreq);
	}
 
	ifreq.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(ifreq.ifr_hwaddr.sa_data, mac, 6);
	ret = ioctl(fd, SIOCSIFHWADDR, &ifreq);
 
	if (ret < 0) {
		ret = -1;
		perror("SIOCSIFHWADDR: ");
		goto ERROR;
	}
 
	if (flag & IFF_UP) {
		ioctl(fd, SIOCGIFFLAGS, &ifreq);
		ifreq.ifr_flags |= IFF_UP;
		ioctl(fd, SIOCSIFFLAGS, &ifreq);
	}
 
ERROR:	
	close(fd);
 
	return ret;
}

int net_eth_get_mac(char *eth_name, unsigned char *mac)
{
	int ret;
	int fd;
	struct ifreq ifreq;
 
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
 
	memset(&ifreq, 0x00, sizeof(struct ifreq));
 
	strcpy(ifreq.ifr_name, eth_name);
	ret = ioctl(fd, SIOCGIFHWADDR, &ifreq);
 
	if (ret < 0) {
		perror("SIOCGIFHWADDR: ");
	}
 
	if (ret == 0 && ifreq.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
		memcpy(mac, ifreq.ifr_hwaddr.sa_data, 6);
	} else {
		ret = -1;
	}
	
	close(fd);
 
	return ret;
}

int net_eth_set_ipv4(char *eth_name, unsigned char *ip_addr)
{

    int sock;
    struct ifreq ifr;
    in_addr_t in_addr;
    struct sockaddr_in sin;
    int ret;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
	perror("socket");
	return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sprintf(ifr.ifr_name, eth_name);

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = inet_addr(ip_addr);
    memcpy(&(ifr.ifr_addr), &sin, sizeof(struct sockaddr));
    ret = ioctl(sock, SIOCSIFADDR, (caddr_t)&ifr, sizeof(struct ifreq));
    if (ret != 0) {
	perror("ioctl ip");
	return -1;
    }



// 	int ret = 0;
// 	int fd;
// 	struct ifreq ifreq;
// 	struct sockaddr_in addr;
 
// 	fd = socket(AF_INET, SOCK_DGRAM, 0);
 
// 	memset(&ifreq, 0x00, sizeof(struct ifreq));
// 	memset(&addr, 0x00, sizeof(struct sockaddr_in));
// 	strcpy(ifreq.ifr_name, eth_name);
 
//     addr.sin_family = AF_INET;
//     addr.sin_port = 0;
//     addr.sin_addr.s_addr = inet_addr(ip);
//     memcpy(&(ifreq.ifr_addr), &addr, sizeof(struct sockaddr));
//     ret = ioctl(fd, SIOCSIFADDR, (caddr_t)&ifreq, sizeof(struct ifreq));
// 	if (ret < 0) {
// 		ret = -1;
// 		perror("SIOCSIFADDR: ");
// 		goto ERROR;
// 	}
 
// ERROR:
// 	close(fd);
 
// 	return ret;
}

int net_eth_get_ipv4(char *eth_name, unsigned char *ip)
{
	int ret;
	int fd;
	struct ifreq ifreq;
	struct sockaddr_in addr;
 
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
 
	memset(&ifreq, 0x00, sizeof(struct ifreq));
	memset(&addr, 0x00, sizeof(struct sockaddr_in));
	strcpy(ifreq.ifr_name, eth_name);
 
	ret = ioctl(fd, SIOCGIFADDR, &ifreq);
 
	if (ret < 0) {
		ret = -1;
		perror("SIOCGIFADDR: ");
		goto ERROR;
	}
 

	memcpy(ip, ifreq.ifr_addr.sa_data+2, 4);
 
ERROR:
	close(fd);
 
	return ret;
}
int set_ip_netmask(const char *name, const char *ip_netmask)
{
    int sock;
    struct ifreq ifr;
    in_addr_t in_addr;
    struct sockaddr_in sin;
    char ip[32] = {0};
    int ret;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) 
    {
        printf("ioctl failed,errno = %d\r\n", errno);
        return -errno; 
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    memset(&sin, 0, sizeof(struct sockaddr_in));

    sprintf(ifr.ifr_name, name);

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = inet_addr(ip_netmask);
    memcpy(&(ifr.ifr_addr), &sin, sizeof(struct sockaddr));
    ret = ioctl(sock, SIOCSIFNETMASK, (caddr_t)&ifr, sizeof(struct ifreq));
    if (ret != 0) 
    {
        printf("ioctl failed,errno = %d\r\n", errno);
        return -errno; 
    }

    return 0;
}

void main()
{
    int ret;
    FILE *fp = NULL;
    char ip_buff[64];


    char *filename = "./IP_PORT_INFO.txt";
    fp = fopen(filename , "r");
    if(fp == NULL)
    {
        printf("file open failed,errno = %d\r\n", errno);
        return -errno;        
    }

    // fgets(ip_buff , sizeof(ip_buff) , fp);
    // sscanf(ip_buff, "server_ip:%d.%d.%d.%d", &server_ip[0], &server_ip[1], &server_ip[2], &server_ip[3]);
    // printf("server_ip is: %d.%d.%d.%d \n", server_ip[0], server_ip[1], server_ip[2], server_ip[3]);

    // fgets(ip_buff , sizeof(ip_buff) , fp);
    // sscanf(ip_buff, "client_ip:%d.%d.%d.%d", &client_ip[0], &client_ip[1], &client_ip[2], &client_ip[3]);
    // printf("client_ip is: %d.%d.%d.%d \n", client_ip[0], client_ip[1], client_ip[2], client_ip[3]);    
	// ret = net_eth_set_ipv4("eth0", client_ip);

    // fgets(ip_buff , sizeof(ip_buff) , fp);
    // sscanf(ip_buff, "client_mask:%d.%d.%d.%d", &client_mask[0], &client_mask[1], &client_mask[2], &client_mask[3]);
    // printf("client_mask is: %d.%d.%d.%d \n", client_mask[0], client_mask[1], client_mask[2], client_mask[3]);
	// ret = set_ip_netmask("eth0", client_mask);    

    // fgets(buff , sizeof(buff) , fp);
    // sscanf(buff, "client_mac:%02x:%02x:%02x:%02x:%02x:%02x", &client_mac[0], &client_mac[1], &client_mac[2], &client_mac[3], &client_mac[4], &client_mac[5]);
    // printf("client_mac is: %02x:%02x:%02x:%02x:%02x:%02x \n", client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
	// ret = net_eth_set_mac("eth0", client_mac);

    memset(ip_buff, 0, sizeof(ip_buff));
    fgets(ip_buff, sizeof(ip_buff), fp);
    sscanf(ip_buff, "server_ip:%s", &server_ip);
    printf("server_ip is: %s \n", server_ip);

    memset(ip_buff, 0, sizeof(ip_buff));
    fgets(ip_buff, sizeof(ip_buff), fp);
    sscanf(ip_buff, "client_ip:%s", &client_ip);
    printf("client_ip is: %s \n", client_ip);    
	ret = net_eth_set_ipv4("ens33", client_ip);

    memset(ip_buff, 0, sizeof(ip_buff));
    fgets(ip_buff, sizeof(ip_buff), fp);
    sscanf(ip_buff, "client_mask:%s", &client_mask);
    printf("client_mask is: %s \n", client_mask);
	ret = set_ip_netmask("ens33", client_mask);

    memset(ip_buff, 0, sizeof(ip_buff));
    fgets(ip_buff, sizeof(ip_buff), fp);
    sscanf(ip_buff, "client_mac:%02x:%02x:%02x:%02x:%02x:%02x", &client_mac[0], &client_mac[1], &client_mac[2], &client_mac[3], &client_mac[4], &client_mac[5]);
    printf("client_mac is: %02x:%02x:%02x:%02x:%02x:%02x \n", client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
	ret = net_eth_set_mac("ens33", client_mac);

    memset(ip_buff, 0, sizeof(ip_buff));
    fgets(ip_buff, sizeof(ip_buff), fp);
    sscanf(ip_buff, "server_port_num:%d", &server_port_num);
    printf("server_port_num is: %d\n", server_port_num);

    memset(ip_buff, 0, sizeof(ip_buff));
    fgets(ip_buff, sizeof(ip_buff), fp);
    sscanf(ip_buff, "client_port_num:%d", &client_port_num);
    printf("client_port_num is: %d\n", client_port_num);

    memset(ip_buff, 0, sizeof(ip_buff));
    fgets(ip_buff, sizeof(ip_buff), fp);
    sscanf(ip_buff, "cmd_port_num:%d", &cmd_port_num);
    printf("cmd_port_num is: %d\n", cmd_port_num);

    fclose(fp);
}

