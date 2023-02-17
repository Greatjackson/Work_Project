#include <stdio.h>                                                       /* for fprintf etc             */
#include <net/if.h>                                                      /* for struct ifreq            */
#include <net/if_arp.h>                                                  /* for ARPHRD_ETHER            */
#include <sys/ioctl.h>                                                   /* for IOCTL's                 */
#include <sys/socket.h>                                                  /* for socket(2)               */
//#include <unistd.h>                                                      /* for close                   */
 
int main(int argc, const char *argv[])
 
{
    int sockfd;
    struct ifreq req;
    char buf[32] = {0};
    char buf_mac[32] = {0x00, 0x04, 0x88, 0x00, 0x50, 0x15};             /* 这里为需要设置的 mac 目标值 */
 
    int i = 0;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("fail to create socket ..!");
        exit(1);
    }
    strcpy(req.ifr_ifrn.ifrn_name, "en1");
 
    /* 获得en1的MAC地址 */
    if (ioctl(sockfd, SIOCGIFHWADDR, &req) < 0) {
        perror("fail to ioctl ");
        close(sockfd);
        exit(1);
    }
    memcpy(buf, req.ifr_ifru.ifru_hwaddr.sa_data, 6);
    for (i = 0; i < 6; i++)
        printf("%02x:", buf[i] & 0xff);
    puts("\b ");//后输出不带"："
 
    memcpy(req.ifr_ifru.ifru_hwaddr.sa_data, buf_mac, 6);
//    strncpy(req.ifr_ifru.ifru_hwaddr.sa_data, buf_mac, 6);
    /* *设置en1的MAC地址 */
    if (ioctl(sockfd, SIOCSIFHWADDR, &req) < 0) {
        perror("fail to ioctl ");
        close(sockfd);
        exit(1);
    }
 
    /* *获得en1的MAC地址 */
    if (ioctl(sockfd, SIOCGIFHWADDR, &req) < 0) {
        perror("fail to ioctl ");
        close(sockfd);
        exit(1);
    }
    close(sockfd);
    memcpy(buf, req.ifr_ifru.ifru_hwaddr.sa_data, 6);
    //strncpy(buf, req.ifr_ifru.ifru_hwaddr.sa_data, 6);
 
    /* *按照xx:xx:xx:xx:xx:xx的格式显示 */
    for (i = 0; i < 6; i++)
        printf("%02x:", buf[i] & 0xff);
    puts("\b ");//后输出不带"："
 
    return 0;
}
 
