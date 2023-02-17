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



unsigned char ip[4];
unsigned char mask[4];
unsigned char mac[6];
unsigned int port_num;

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

void main()
{
    int ret;
    FILE *fp = NULL;
    char ip_buff[64];
	char buff[64];
    char *mert;
	unsigned char mask[4] = {255, 255, 255, 0};

    char *filename = "./IP_PORT_INFO.txt";
    fp = fopen(filename , "r");
    printf("%d \n",sizeof(buff));
    mert = fgets(ip_buff , sizeof(ip_buff) , fp);
    if(mert == NULL){
        printf("读取失败!!!");
        return;
    }
    sscanf(ip_buff, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
    printf("IP is: %d.%d.%d.%d \n", ip[0], ip[1], ip[2], ip[3]);
	ret = net_eth_set_ipv4("ens33", ip_buff);

    fgets(buff , sizeof(buff) , fp);
    sscanf(buff, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    printf("MAC is: %02x:%02x:%02x:%02x:%02x:%02x \n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	net_eth_set_mac("ens33", mac);

    fgets(buff, sizeof(buff) , fp);
    sscanf(buff, "%d", &port_num);
    printf("PORT_NUM is: %d\n", port_num);

    fclose(fp);

}

