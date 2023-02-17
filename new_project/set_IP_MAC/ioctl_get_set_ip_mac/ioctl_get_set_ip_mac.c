#include <sys/socket.h>
#include <linux/route.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
 
/*
 * 启动/停用 网卡状态 (类似 ifconfig ethx up或ifconfig ethx down)
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @state: "up": 启动网卡, "down": 停用网卡
 * @ret: 0: 成功, -1: 失败
 */
int net_eth_state(char *eth_name, char *state)
{
	int ret = 0;
	int fd;
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
 
	if (strcmp("up", state) == 0) {
		ifreq.ifr_flags |= IFF_UP;
	} else {
		ifreq.ifr_flags &= ~IFF_UP;
	}
 
	ret = ioctl(fd, SIOCSIFFLAGS, &ifreq);
	if (ret < 0) {
		ret = -1;
		perror("SIOCSIFFLAGS: ");
		goto ERROR;
	}
ERROR:
	close(fd);
 
	return ret;
}
 
/*
 * 查看网卡是否已经启动
 * @ret: 0: down, 1: up, -1: 错误
 */
int net_eth_state_is_up(char *eth_name)
{
	int ret;
	int fd;
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
 
	if (ifreq.ifr_flags & IFF_UP) {
		ret = 1;
	} else {
		ret = 0;
	}
 
ERROR:
	close(fd);
 
	return ret;
}
 
/*
 * 获取网卡的MAC地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @mac: 返回6字节mac地址, 如unsigned char mac[6] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB};
 * @ret: 0: 成功, -1: 失败
 */
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
 
/*
 * 修改网卡的MAC地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @mac: 6字节mac地址, 如unsigned char mac[6] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB};
 *       类似于 ifconfig ethx hw ether 12:34:56:78:90:AB
 * @ret: 0: 成功, -1: 失败
 */
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
 
	/*
	 * 如果网卡是启动的,设置MAC地址需要先停止网卡
	 */
	if (flag & IFF_UP) {
		ifreq.ifr_flags &= ~IFF_UP;
		ioctl(fd, SIOCSIFFLAGS, &ifreq);
	}
 
	/*
	 * 配置MAC地址
	 */
	ifreq.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(ifreq.ifr_hwaddr.sa_data, mac, 6);
	ret = ioctl(fd, SIOCSIFHWADDR, &ifreq);
 
	if (ret < 0) {
		ret = -1;
		perror("SIOCSIFHWADDR: ");
		goto ERROR;
	}
 
	/*
	 * 如果恢复网卡的工作状态
	 */
	if (flag & IFF_UP) {
		ioctl(fd, SIOCGIFFLAGS, &ifreq);
		ifreq.ifr_flags |= IFF_UP;
		ioctl(fd, SIOCSIFFLAGS, &ifreq);
	}
 
ERROR:	
	close(fd);
 
	return ret;
}
 
 
/*
 * 获取网卡ip地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @ip: 返回4字节ip地址, 如char ip[4] = {10, 10, 10, 3};即: 10.10.10.3
 * @netmask: 返回4字节netmask地址, 如char netmask[4] = {0xff, 0xff, 0xff, 0};即: 255.255.255.0
 * @ret: 0: 成功, -1: 不能获取ip地址
 */
int net_eth_get_ipv4(char *eth_name, unsigned char *ip, unsigned char *netmask)
{
	int ret;
	int fd;
	struct ifreq ifreq;
 
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
 
	memset(&ifreq, 0x00, sizeof(struct ifreq));
	strcpy(ifreq.ifr_name, eth_name);
 
	/*
	 * 获取IP地址
	 */
	ret = ioctl(fd, SIOCGIFADDR, &ifreq);
 
	if (ret < 0) {
		ret = -1;
		perror("SIOCGIFADDR: ");
		goto ERROR;
	}
 
	if (ifreq.ifr.sa_family != AF_INET) {
		ret = -1;
		goto ERROR;
	}
 
	struct sockaddr_in *addr = (struct sockaddr_in *)&(ifreq.ifr);
	memcpy(ip, &(addr->sin.s), 4);
 
 
	/*
	 * 获取netmask
	 */
	ret = ioctl(fd, SIOCGIFNETMASK, &ifreq);
 
	if (ret < 0) {
		ret = -1;
		perror("SIOCGIFNETMASK: ");
		goto ERROR;
	}
 
	if (ifreq.ifr_netmask.sa_family != AF_INET) {
		ret = -1;
		goto ERROR;
	}
 
	addr = (struct sockaddr_in *)&(ifreq.ifr_netmask);
	memcpy(netmask, &(addr->sin.s), 4);
 
ERROR:
	close(fd);
 
	return ret;
}
 
/*
 * 设置网卡ip地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @ip: 返回4字节ip地址, 如char ip[4] = {10, 10, 10, 3};即: 10.10.10.3
 * @netmask: 返回4字节netmask地址, 如char netmask[4] = {0xff, 0xff, 0xff, 0};即: 255.255.255.0
 * @ret: 0: 成功, -1: 不能获取ip地址
 */
int net_eth_set_ipv4(char *eth_name, unsigned char *ip, unsigned char *netmask)
{
	int ret = 0;
	int fd;
	struct ifreq ifreq;
 
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
 
	memset(&ifreq, 0x00, sizeof(struct ifreq));
	strcpy(ifreq.ifr_name, eth_name);
 
	/*
	 * 设置IP地址
	 */
	ifreq.ifr.sa_family = AF_INET;
	struct sockaddr_in *addr = (struct sockaddr_in *)&(ifreq.ifr);
	memcpy(&(addr->sin.s), ip, 4);
	ret = ioctl(fd, SIOCSIFADDR, &ifreq);
	if (ret < 0) {
		ret = -1;
		perror("SIOCSIFADDR: ");
		goto ERROR;
	}
 
	/*
	 * 获取netmask
	 */
	ifreq.ifr_netmask.sa_family = AF_INET;
	addr = (struct sockaddr_in *)&(ifreq.ifr_netmask);
	memcpy(&(addr->sin.s), netmask, 4);
	ret = ioctl(fd, SIOCSIFNETMASK, &ifreq);
	if (ret < 0) {
		ret = -1;
		perror("SIOCSIFNETMASK: ");
		goto ERROR;
	}
ERROR:
	close(fd);
 
	return ret;
}
 
#include <stdlib.h>
/*
 * 添加默认网关
 * @gw: 4字节地址, 如char gw[4] = {10, 10, 10, 1};即: 10.10.10.1
 * @ret: 0: 成功, -1: 失败
 * 
 * 注意: 如果想删除网卡相关的所有路由表可以直接把网卡down,即ifconfig ethx down
 */
int net_route_add_default_gateway(unsigned char *gw)
{
	char buf[128];
	sprintf(buf, "route add default gw %d.%d.%d.%d", gw[0], gw[1], gw[2], gw[3]);
	return system(buf);
}
 
/*
 * 获取默认网关
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @gw: 获取4字节地址, 如char gw[4] = {10, 10, 10, 1};即: 10.10.10.1
 * @ret: 0: 成功, -1: 失败
 * 
 * 注意: 如果想删除网卡相关的所有路由表可以直接把网卡down,即ifconfig ethx down
 */
int net_route_get_default_gateway(char *eth_name, unsigned char *gw)
{
	int ret = -1;
	FILE *fp;
	char devname[64];
	unsigned long d, g, m;
	int r;
	int flgs, ref, use, metric, mtu, win, ir;
 
	fp = fopen("/proc/net/route", "r");
 
	/* Skip the first line. */
	r = fscanf(fp, "%*[^\n]\n");
 
	if (r < 0) {
		/* Empty line, read error, or EOF. Yes, if routing table
		 * is completely empty, /proc/net/route has no header.
		 */
		ret = -1;
		goto ERROR;
	}
 
	while (1) {
		r = fscanf(fp, "%63s%lx%lx%X%d%d%d%lx%d%d%d\n",
				devname, &d, &g, &flgs, &ref, &use, &metric, &m,
				&mtu, &win, &ir);
 
		if (r != 11) {
			if ((r < 0) && feof(fp)) { /* EOF with no (nonspace) chars read. */
				break;
			}
		}
 
		/*
		 * # cat /proc/net/route 
		 * Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT                                                       
		 * eth0    00000000        013CA8C0        0003    0       0       0       00000000        0       0       0                                                                               
		 * eth0    003CA8C0        00000000        0001    0       0       0       00FFFFFF        0       0       0
		 * 默认网关的特性: dst为0，netmask为0, Gateway不为0
		 */
		if (strcmp(devname, eth_name) == 0 &&\
			(flgs & RTF_GATEWAY) && \
			(flgs & RTF_UP) && \
			g != 0 && d == 0 && m == 0) {
			memcpy(gw, &g, 4);
			ret = 0;
			break;
		}
	}
 
ERROR:
	fclose(fp);
	return ret;
}
 
 
void main(void)
{
	unsigned char gw[4] = {1, 1, 1, 1};
	//net_route_add_default_gateway(gw);
 
	net_route_get_default_gateway("ens33", gw);
	printf("gw: %d.%d.%d.%d\n", gw[0], gw[1], gw[2], gw[3]);
 
//	return;
 
	int ret;
	unsigned char ip[4] = {10, 10, 10, 3};
	unsigned char mask[4] = {255, 0, 0, 0};
 
	ret = net_eth_set_ipv4("ens33", ip, mask);
	printf("ret1: %d\n", ret);
 
	ret = net_eth_get_ipv4("ens33", ip, mask);
	printf("ret: %d\n", ret);
	printf("ip: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
	printf("netmask: %d.%d.%d.%d\n", mask[0], mask[1], mask[2], mask[3]);
 
 
//	return;
 
	unsigned char mac[6] = {0xEE, 0x08, 0xE4, 0x41, 0xF1, 0xF4};
	net_eth_set_mac("ens33", mac);
	net_eth_get_mac("ens33", mac);
 
	printf("mac: %X:%X:%X:%X:%X:%X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return;
}
 
