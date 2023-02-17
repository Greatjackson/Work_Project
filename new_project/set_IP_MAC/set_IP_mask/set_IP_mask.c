#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

int set_ip_netmask(const char *name, const char *ip_addr, const char *ip_netmask)
{
    int sock;
    struct ifreq ifr;
    in_addr_t in_addr;
    struct sockaddr_in sin;
    char ip[32] = {0};
    int ret;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
	perror("socket");
	return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    memset(&sin, 0, sizeof(struct sockaddr_in));

    sprintf(ifr.ifr_name, name);

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = inet_addr(ip_addr);
    memcpy(&(ifr.ifr_addr), &sin, sizeof(struct sockaddr));
    ret = ioctl(sock, SIOCSIFADDR, (caddr_t)&ifr, sizeof(struct ifreq));
    if (ret != 0) {
	perror("ioctl ip");
	return -1;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = inet_addr(ip_netmask);
    memcpy(&(ifr.ifr_addr), &sin, sizeof(struct sockaddr));
    ret = ioctl(sock, SIOCSIFNETMASK, (caddr_t)&ifr, sizeof(struct ifreq));
    if (ret != 0) {
	perror("ioctl netmask");
	return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{

    set_ip_netmask("ens33", "192.168.12.11", "255.255.255.0");

    return 0;
}

