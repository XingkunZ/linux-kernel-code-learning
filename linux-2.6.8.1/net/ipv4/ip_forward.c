/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP forwarding functionality.
 *		
 * Version:	$Id: ip_forward.c,v 1.48 2000/12/13 18:31:48 davem Exp $
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip_input.c for 
 *					history.
 *		Dave Gregorich	:	NULL ip_rt_put fix for multicast 
 *					routing.
 *		Jos Vos		:	Add call_out_firewall before sending,
 *					use output device for accounting.
 *		Jos Vos		:	Call forward firewall after routing
 *					(always use output device).
 *		Mike McLagan	:	Routing by source
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>

static inline int ip_forward_finish(struct sk_buff *skb)
{
    // 更新统计信息
	struct ip_options * opt	= &(IPCB(skb)->opt);

	IP_INC_STATS_BH(IPSTATS_MIB_OUTFORWDATAGRAMS);

	if (unlikely(opt->optlen)) // 检查是否包含IP选项
    // 包含：
		ip_forward_options(skb); 
    // 否则：
    // 转入IP层的发送流程
	return dst_output(skb);
}

int ip_forward(struct sk_buff *skb)
{
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))
		goto drop;

	// 如果设置了router_alert的选项，则必须调用ip_call_ra_chain处理数据包
	// ip_call_ra_chain会将数据包交给所有原始套接字。
	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;

	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	skb->ip_summed = CHECKSUM_NONE;
	
	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */

	iph = skb->nh.iph;

	if (iph->ttl <= 1) // 如果ttl减为0，则报告数据包无效
		goto too_many_hops;

	if (!xfrm4_route_forward(skb))
		goto drop;

	iph = skb->nh.iph;
	rt = (struct rtable*)skb->dst;

	// 检查是否同时设置了严格路由标志和rt_uses_gateway标志，
	// 如果都使用了，则不能用严格路由选择
	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;

	/* We are about to mangle packet. Copy it! */
	// 即将要修改数据包信息（ttl,checksum）则先拷贝一份
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->u.dst.dev)+rt->u.dst.header_len))
		goto drop;
	iph = skb->nh.iph;

	/* Decrease ttl after skb cow done */
	// IP协议头部的TTL字段减1
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	// 如果目的地址不可达，则通知发送数据的源端，重定向到主机
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr)
		ip_rt_send_redirect(skb);

	skb->priority = rt_tos2priority(iph->tos);

	// 假设没有NF_IP_FORWARD钩子，则调用ip_forward_finish函数完成转发的最后操作
	return NF_HOOK(PF_INET, NF_IP_FORWARD, skb, skb->dev, rt->u.dst.dev,
		       ip_forward_finish);

sr_failed:
        /*
	 *	Strict routing permits no gatewaying
	 */
		// 返回一个ICMP包，报告目的地不可达
         icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
         goto drop;

too_many_hops:
        /* Tell the sender its packet died... */
		// 返回一个ICMP包，报告数据包已失效
        icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
