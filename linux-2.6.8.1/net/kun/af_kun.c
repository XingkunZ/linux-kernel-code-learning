/*
 * KUN
 * 
 * Authors: Xingkun Zhao <xingkunz.github.io>
 */

#include <linux/config.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/netfilter_ipv4.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/smp_lock.h>
#include <linux/inet.h>
#include <linux/igmp.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/raw.h>
#include <net/icmp.h>
#include <net/ipip.h>
#include <net/kun.h>
#include <net/xfrm.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#endif

// kun协议的内核缓存指针
static kmem_cache_t * kun_sk_cachep;

// 清除KUN协议族套接字内存单元
static void kun_sock_destruct (struct sock *sk)
{
    __skb_queue_purge(&sk->sk_receive_queue);
    __skb_queue_purge(&sk->sk_error_queue);
    dst_release(sk->sk_dst_cache);
}

// KUN协议族套接字操作集[struct proto_ops]变量
struct proto_ops kun_sk_ops = {
    .family = PF_KUN,
    .owner  = THIS_MODULE,
    .release = kun_release,
    .sendmsg = kun_sendmsg,
    .recvmsg = kun_recvmsg,
};

// KUN协议族管理类型，管理创建方法
struct net_protocol_family kun_family_ops = {
    .family = PF_KUN,
    .create = kun_create,
    .owner  = THIS_MODULE,
};

// 创建KUN协议族套接字
static int kun_create(struct socket * sock, int protocol)
{
    struct sock *sk;
    struct list_head *p;

    sock->state = SS_UNCONNECTED;
    sock->ops   = & kun_sk_ops;

    //initialize sk
    sk = sk_alloc(PF_KUN, GFP_KERNEL, sizeof(struct sock), kun_sk_cachep);
    if(!sk) return -1;

    sock_init_data(sock, sk);
    sk_set_owner(sk, THIS_MODULE);
    sk->sk_destruct = kun_sock_destruct;
    sk->sk_zapped   = 0;
    sk->sk_family   = PF_KUN;
    sk->sk_protocol = 0;
    sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
    return 0;
}

// 通过KUN协议族套接字发送数据
static int kun_sendmsg()
{

}

// 通过KUN协议族套接字接收数据
static int kun_recvmsg()
{

}

// 释放KUN协议族套接字
static int kun_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    
    if(!sk) return 0;
    sock->sk = NULL;
    return kun_release_sock(sk,0);
}

// 根据KUN协议族套接字特点释放其结构
static void kun_release_sock(struct sock *sk)
{

}

// 初始化KUN协议族套接字
int __init kun_sock_init(void)
{
    (void)sock_register(&kun_family_ops);
    mpls_sk_cachep = kmem_cache_create("kun_sock", sizeof(struct sock), 0, SLAB_HWCACHE_ALIGN, 0, 0);
    return 0;
}

// 注销KUN协议族套接字
void __exit kun_sock_exit(void)
{
    int result = 0;
    result = kmem_cache_destroy(kun_sk_cachep);
    (void)sock_unregister(PF_KUN);
}