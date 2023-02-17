
#include<stdio.h>
#include<stdlib.h>
 
#define ARM_MAX_NUM 10  /*最大限制10个*/

struct IP_ADDR_ST
{
	unsigned int ip_addr[4];
	unsigned int port_num;
    unsigned int mac_addr[6];
};
 
void main()
{
    FILE *fp = NULL;
    char buff[64]; /*读取文件缓冲区*/
    char *mert;
    struct IP_ADDR_ST ip_addr; /*结构体保存IP地址*/
    char *filename = "./IP_PORT_INFO.txt"; /*从哪儿读取数据*/
    fp = fopen(filename , "r"); /*打开文件只读*/
    printf("%d \n",sizeof(buff));
    mert = fgets(buff , sizeof(buff) , fp); /*获取第一行数据*/
    if(mert == NULL){
        printf("读取失败!!!");
        return;
    }
    sscanf(buff, "%d.%d.%d.%d", &ip_addr.ip_addr[0], &ip_addr.ip_addr[1], &ip_addr.ip_addr[2], &ip_addr.ip_addr[3]);
    printf("IP_ADDR is: %d.%d.%d.%d \n", ip_addr.ip_addr[0], ip_addr.ip_addr[1], ip_addr.ip_addr[2], ip_addr.ip_addr[3]);
    
    fgets(buff, sizeof(buff) , fp);
    sscanf(buff, "%d", &ip_addr.port_num);
    printf("PORT_NUM is: %d\n", ip_addr.port_num);

    fgets(buff , sizeof(buff) , fp);
    sscanf(buff, "%02x:%02x:%02x:%02x:%02x:%02x", &ip_addr.mac_addr[0], &ip_addr.mac_addr[1], &ip_addr.mac_addr[2],
                                     &ip_addr.mac_addr[3], &ip_addr.mac_addr[4], &ip_addr.mac_addr[5]);
    printf("MAC_ADDR is: %02x:%02x:%02x:%02x:%02x:%02x \n", ip_addr.mac_addr[0], ip_addr.mac_addr[1], ip_addr.mac_addr[2],
                                                        ip_addr.mac_addr[3], ip_addr.mac_addr[4], ip_addr.mac_addr[5]);

    fclose(fp);

}
