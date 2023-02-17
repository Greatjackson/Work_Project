#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <errno.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/netlink.h>
#include <linux/if_arp.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netdb.h>


/*
 * 启动/停用 网卡状态 (类似 ifconfig ethx up或ifconfig ethx down)
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @state: "up": 启动网卡, "down": 停用网卡
 * @ret: 0: 成功, -1: 失败
 */
int rtnetlink_eth_state(char *eth_name, char *state)
{
	int ret;
	struct rtnl_link *link, *link_conf;
	struct nl_sock *sk = nl_socket_alloc();
	nl_connect(sk, NETLINK_ROUTE);

	ret = rtnl_link_get_kernel(sk, 0, eth_name, &link);

	if (ret < 0) {
		printf("Err: %s not found!!!n", eth_name);
		ret = -1;
		goto ERROR1;
	}

	link_conf = rtnl_link_alloc();

	if (strcmp("up", state) == 0) {
		rtnl_link_set_flags(link_conf, IFF_UP);
	} else if (strcmp("down", state) == 0) {
		rtnl_link_unset_flags(link_conf, IFF_UP);
	} else {
		ret = -1;
		printf("Err: %s para error!!!n", state);
		goto ERROR2;
	}
	
	ret = rtnl_link_change(sk, link, link_conf, 0);

	if (ret < 0) {
		printf("Err: rtnetlink_eth_state: %dn", ret);
	}

ERROR2:
	rtnl_link_put(link); rtnl_link_put(link_conf);

ERROR1:
	nl_close(sk);
	nl_socket_free(sk);
	return ret;
}

/*
 * 修改网卡的MAC地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @mac: 6字节mac地址, 如unsigned char mac[6] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB};
 *       类似于 ifconfig ethx hw ether 12:34:56:78:90:AB
 * @ret: 0: 成功, -1: 失败
 */
int rtnetlink_eth_set_mac(char *eth_name, unsigned char *mac)
{
	int ret;
	struct rtnl_link *link, *link_conf;
	struct nl_addr *hw_addr;
	struct nl_sock *sk = nl_socket_alloc();
	nl_connect(sk, NETLINK_ROUTE);

	ret = rtnl_link_get_kernel(sk, 0, eth_name, &link);

	if (ret < 0) {
		printf("Err: %s not found!!!n", eth_name);
		ret = -1;
		goto ERROR1;
	}

	unsigned int if_flag = rtnl_link_get_flags(link);

	/*
	 * 只有在网卡不启用的时候才能设置MAC地址,所以如果网卡已经启用,
	 * 首先停用网卡,然后设置MAC地址,设置完成后，再次启动网卡
	 */
	if (if_flag & IFF_UP) {
		rtnetlink_eth_state(eth_name, "down");
	}

	link_conf = rtnl_link_alloc();

	/*
	 * AF_LLC: 地址簇是MAC地址
	 */
	hw_addr = nl_addr_build(AF_LLC, mac, 6);
	rtnl_link_set_addr(link_conf, hw_addr);

	ret = rtnl_link_change(sk, link, link_conf, 0);

	if (ret < 0) {
		printf("Err: rtnetlink_eth_change_mac: %dn", ret);
	}

	if (if_flag & IFF_UP) {
		rtnetlink_eth_state(eth_name, "up");
	}
	
	nl_addr_put(hw_addr);
	rtnl_link_put(link);
	rtnl_link_put(link_conf);

ERROR1:
	nl_close(sk);
	nl_socket_free(sk);
	return ret;
}

/*
 * 获取网卡的MAC地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @mac: 返回6字节mac地址, 如unsigned char mac[6] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB};
 * @ret: 0: 成功, -1: 失败
 */
int rtnetlink_eth_get_mac(char *eth_name, unsigned char *mac)
{
	int ret;
	struct rtnl_link *link;
	struct nl_addr *hw_addr;
	struct nl_sock *sk = nl_socket_alloc();
	nl_connect(sk, NETLINK_ROUTE);

	ret = rtnl_link_get_kernel(sk, 0, eth_name, &link);

	if (ret < 0) {
		printf("Err: %s not found!!!", eth_name);
		ret = -1;
		goto ERROR1;
	}

	hw_addr = rtnl_link_get_addr(link);

	if (nl_addr_get_len(hw_addr) != 6 || nl_addr_get_family(hw_addr) != AF_LLC) {
		ret = -1;
		printf("Err: hw_addr len or family error!!!n");
		goto ERROR2;
	}

	unsigned char *pmac = (unsigned char *)nl_addr_get_binary_addr(hw_addr);
	memcpy(mac, pmac, 6);
	
ERROR2:
	rtnl_link_put(link);

ERROR1:
	nl_close(sk);
	nl_socket_free(sk);
	return ret;
}


static int ipv4_netmask2prefixlen(unsigned char *netmask)
{
	int count  = 0;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 8; j++) {
			if ((netmask[i] & (0x01<<j)) != 0) {
				count++;
			}
		}
	}
	return count;
}


static void ipv4_prefixlen2netmask(int prefixlen, unsigned char *netmask)
{
	int i;

	memset(netmask, 0x00, 4);

	int byte = prefixlen / 8;
	int bit = prefixlen % 8;

	for (i = 0; i < byte; i++) {
		netmask[i] = 0xff;
	}

	netmask[byte] = 0;

	for (i = 0; i < bit; i++) {
		netmask[byte] |= (0x01<<(7 - i));
	}
}


struct get_ipv4_addr_ctx_t {
	struct nl_sock *sk;
	int flag; /* 是否找到ip */
	int index; /* 网卡索引 */
	unsigned char *ip;
	unsigned char *netmask;
};


static void get_ipv4_addr_cache_cb(struct nl_object *obj, void *arg)
{
	struct get_ipv4_addr_ctx_t *ctx = (struct get_ipv4_addr_ctx_t *)arg;
	struct rtnl_addr *rtnl_addr = (struct rtnl_addr *)obj;

	if (rtnl_addr_get_ifindex(rtnl_addr) == ctx->index) {
		struct nl_addr *nl_addr = rtnl_addr_get_local(rtnl_addr);

		if (nl_addr_get_family(nl_addr) == AF_INET && nl_addr_get_len(nl_addr) == 4) {
			ctx->flag = 0x01;
			int netmask_prefixlen = rtnl_addr_get_prefixlen(rtnl_addr);
			char *ip = (char *)nl_addr_get_binary_addr(nl_addr);
			memcpy(ctx->ip, ip, 4);
			if (netmask_prefixlen <= 32) {
				ipv4_prefixlen2netmask(netmask_prefixlen, ctx->netmask);
			}
		}
	}
}


/*
 * 获取网卡ip地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @ip: 返回4字节ip地址, 如char ip[4] = {10, 10, 10, 3};即: 10.10.10.3
 * @netmask: 返回4字节netmask地址, 如char netmask[4] = {0xff, 0xff, 0xff, 0};即: 255.255.255.0
 * @ret: 0: 成功, -1: 不能获取ip地址
 */
int rtnetlink_eth_get_ipv4_addr(char *eth_name, unsigned char *ip, unsigned char *netmask)
{
	int ret = 0;
	struct nl_cache *addr_cache;
	struct rtnl_link *link;
	struct nl_sock *sk = nl_socket_alloc();
	nl_connect(sk, NETLINK_ROUTE);

	ret = rtnl_link_get_kernel(sk, 0, eth_name, &link);

	if (ret < 0) {
		printf("Err: %s not found!!!n", eth_name);
		ret = -1;
		goto ERROR1;
	}

	struct get_ipv4_addr_ctx_t ctx;
	memset(&ctx, 0x00, sizeof(struct get_ipv4_addr_ctx_t));

	ctx.index = rtnl_link_get_ifindex(link);
	ctx.ip = ip;
	ctx.netmask = netmask;

	rtnl_addr_alloc_cache(sk, &addr_cache);
	nl_cache_foreach(addr_cache, get_ipv4_addr_cache_cb, &ctx);

	if (ctx.flag == 0) {
		ret = -1;
		printf("Err: %s not find ip!!!n", eth_name);
	} 

	nl_cache_put(addr_cache);
	rtnl_link_put(link);

ERROR1:
	nl_close(sk);
	nl_socket_free(sk);
	return ret;
}

static void del_ipv4_addr_cache_cb(struct nl_object *obj, void *arg)
{
	struct get_ipv4_addr_ctx_t *ctx = (struct get_ipv4_addr_ctx_t *)arg;
	struct rtnl_addr *rtnl_addr = (struct rtnl_addr *)obj;

	if (rtnl_addr_get_ifindex(rtnl_addr) == ctx->index) {
		struct nl_addr *nl_addr = rtnl_addr_get_local(rtnl_addr);

		if (nl_addr_get_family(nl_addr) == AF_INET && nl_addr_get_len(nl_addr) == 4) {
			int ret = rtnl_addr_delete(ctx->sk, rtnl_addr, 0);
			if (ret < 0) {
				printf("Err: rtnl_addr_delete:%d!!!n", ret);
			}
		}
	}
}


/*
 * 删除网卡ip地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @ip: 返回4字节ip地址, 如char ip[4] = {10, 10, 10, 3};即: 10.10.10.3
 * @netmask: 返回4字节netmask地址, 如char netmask[4] = {0xff, 0xff, 0xff, 0};即: 255.255.255.0
 * @ret: 0: 成功, -1: 不能获取ip地址
 */
int rtnetlink_eth_del_ipv4_addr(char *eth_name)
{
	int ret = 0;
	struct nl_cache *addr_cache;
	struct rtnl_link *link;
	struct nl_sock *sk = nl_socket_alloc();
	nl_connect(sk, NETLINK_ROUTE);

	ret = rtnl_link_get_kernel(sk, 0, eth_name, &link);

	if (ret < 0) {
		printf("Err: %s not found!!!n", eth_name);
		ret = -1;
		goto ERROR1;
	}

	struct get_ipv4_addr_ctx_t ctx;
	memset(&ctx, 0x00, sizeof(struct get_ipv4_addr_ctx_t));

	ctx.index = rtnl_link_get_ifindex(link);
	ctx.sk = sk;

	rtnl_addr_alloc_cache(sk, &addr_cache);
	nl_cache_foreach(addr_cache, del_ipv4_addr_cache_cb, &ctx);

	nl_cache_put(addr_cache);
	rtnl_link_put(link);

ERROR1:
	nl_close(sk);
	nl_socket_free(sk);
	return ret;
}


/*
 * 设置网卡ip地址
 * @eth_name: 网卡名, 如:eth0, wlan0..
 * @ip: 返回4字节ip地址, 如char ip[4] = {10, 10, 10, 3};即: 10.10.10.3
 * @netmask: 返回4字节netmask地址, 如char netmask[4] = {0xff, 0xff, 0xff, 0};即: 255.255.255.0
 * @ret: 0: 成功, -1: 不能获取ip地址
 * 注意: 一般情况下网卡可以设置多个IP地址，这个函数只设置1个IP地址,设置过程是首先删除原来的IP地址,然后在添加新的IP地址
 */
int rtnetlink_eth_set_ipv4_addr(char *eth_name, unsigned char *ip, unsigned char *netmask)
{
	int ret = 0;
	struct rtnl_link *link;
	struct nl_sock *sk = nl_socket_alloc();
	nl_connect(sk, NETLINK_ROUTE);

	ret = rtnl_link_get_kernel(sk, 0, eth_name, &link);

	if (ret < 0) {
		printf("Err: %s not found!!!n", eth_name);
		ret = -1;
		goto ERROR1;
	}

	struct rtnl_addr *new_rtnl_addr = rtnl_addr_alloc();

	int if_index = rtnl_link_get_ifindex(link);
	/*
	 * 在rtnl_addr中,netmask用ip地址有效长度表示,
	 * 如: 255.225.0.0有效长度为16
	 */
	int netmask_prefixlen = ipv4_netmask2prefixlen(netmask);
	
	rtnl_addr_set_ifindex(new_rtnl_addr, if_index);
	rtnl_addr_set_family(new_rtnl_addr, AF_INET);

	struct nl_addr *ip_addr = nl_addr_build(AF_INET, ip, 4);
	rtnl_addr_set_local(new_rtnl_addr, ip_addr);
	nl_addr_put(ip_addr);

	rtnl_addr_set_prefixlen(new_rtnl_addr, netmask_prefixlen);

	unsigned char broadcast[4];

	for (int i = 0; i< 4; i++) {
		broadcast[i] = (netmask[i] & ip[i]);
		broadcast[i] |= ~netmask[i];
	}

	struct nl_addr *broadcast_addr = nl_addr_build(AF_INET, broadcast, 4);
	rtnl_addr_set_broadcast(new_rtnl_addr, broadcast_addr);
	nl_addr_put(broadcast_addr);

	/*
	 * 添加地址之前首先删除原来的地址
	 */
	rtnetlink_eth_del_ipv4_addr(eth_name);

	ret = rtnl_addr_add(sk, new_rtnl_addr, 0);

	if (ret < 0) {
		printf("Err: rtnl_addr_add: %dn", ret);
	}

	rtnl_addr_put(new_rtnl_addr);
	rtnl_link_put(link);

ERROR1:
	nl_close(sk);
	nl_socket_free(sk);
	return ret;
}



void test_rtnetlink_manage(void)
{

	unsigned char ip[4] = {192, 168, 60, 85};
	unsigned char netmask[] = {255, 255, 255, 0};
	//rtnetlink_eth_del_ipv4_addr("wlan0");
	rtnetlink_eth_set_ipv4_addr("eth0", ip, netmask);


	return;
	//getifaddrs()
}
