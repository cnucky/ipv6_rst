/*************************************************************************
 > File Name      : test.c
 > Author         : yangqx
 > 
 > Created Time   : 2017年06月09日 星期五 09时36分14秒
 > Description    : 
 ************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
// #include <linux/skbuff.h>
// #include <linux/netdevice.h>
// #include <linux/ipv6.h>
// #include <linux/netfilter_ipv6.h>
// #include <net/ipv6.h>
#include "datadump.h"

struct tcp_option_ts
{
    unsigned int tsval;
    unsigned int tsecr;
};

int send_tcp_rst_ipv6(struct sk_buff *skb)
{
 	struct ethhdr*	eth 		= NULL;
 	struct ethhdr*	eth_new 	= NULL;
 	struct ipv6hdr*	ipv6 		= NULL;
 	struct ipv6hdr*	ipv6_new	= NULL;
 	struct tcphdr*	tcp 		= NULL;
 	struct tcphdr*	tcp_new 	= NULL;
 	struct sk_buff*	skb_new 	= NULL;
 	int network_len = 0;

 	if (NULL == skb)
 	{
 		return -1;
 	}

    //获取原有eth头,ipv6头,tcp头
    eth  = (struct ethhdr *)((u8 *)(skb->data) - ETH_HLEN);
 	ipv6 = ipv6_hdr(skb);    
    tcp  = get_tcphdr(skb, ipv6);
    if (NULL == tcp)
    {
        return -1;
    } 		
	network_len = (u8 *)tcp - (u8 *)ipv6 + tcp->doff * 4;		//network_len = ip层长度+tcp层长度

    if (tcp->rst)					//已经是RST
    {
    	printk("already reset\n");
    	return 0;
    }

    //构造TCP RST包
    //1.复制一个新的ipv6头,tcp头,eth头
    skb_new = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb), GFP_ATOMIC);
    if (NULL == skb_new)
    {
    	return -1;
    }
    if (skb_new->len < network_len)
    {
    	skb_put(skb_new, network_len - skb_new->len);
    }
    eth_new  = (struct ethhdr *)((u8 *)(skb_new->data) - ETH_HLEN);
    ipv6_new = (struct ipv6hdr *)(skb_new->data);
    tcp_new  = get_tcphdr(skb_new, ipv6_new);
    if (NULL == tcp_new)
    {
    	kfree_skb(skb_new);
        return -1;
    }

    //2.设置新的ipv6头saddr，daddr，payload_len字段信息，其他字段与原来保持一致
    memcpy((char*)&(ipv6_new->saddr), (char*)&(ipv6->daddr), sizeof(struct  in6_addr) );
    memcpy((char*)&(ipv6_new->daddr), (char*)&(ipv6->saddr), sizeof(struct  in6_addr) );
    //净荷长度=ipv6扩展头部+传输层长度+应用层长度 (不包含ipv6固定头部长度)
    ipv6_new->payload_len = htons(network_len - sizeof(struct ipv6hdr));	//RST包的应用层长度为0

    //3.设置新的TCP头字段信息
    tcp_new->source = tcp->dest;
    tcp_new->dest   = tcp->source;
    if (tcp->ack)					//异常关闭链接
    {
    	tcp_new->ack = 0;
    	tcp_new->seq = tcp->ack_seq;
    	tcp_new->ack_seq = 0;
    }
    else //老skb为到端口不存在的链接请求
    {
    	tcp_new->ack = 1;
    	tcp_new->seq = 0;
    	tcp_new->ack_seq = htonl(				
    							ntohl(tcp->seq) + 
    							ntohs(ipv6->payload_len) +
    							sizeof(struct ipv6hdr) - network_len
    						); 	//32位确认号ack_seq=原序号+应用层数据长度
    }
    tcp_new->rst = 1;
    tcp_new->syn = 0;
    tcp_new->psh = 0;
    tcp_new->window = htons(250);
    tcp_new->urg_ptr = 0;
    if (tcp_new->doff * 4 - sizeof(struct tcphdr) == 12)
    {
        struct tcp_option_ts *tcp_opt;
        struct tcp_option_ts *tcp_opt_new;

        tcp_opt = (struct tcp_option_ts *)((char *)tcp + sizeof(struct tcphdr) + 4);
        tcp_opt_new = (struct tcp_option_ts *)((char *)tcp_new + sizeof(struct tcphdr) + 4);
        tcp_opt_new->tsval = htonl(ntohl(tcp_opt->tsecr) + 100);	//疑点：此处为什么加100
        tcp_opt_new->tsecr = tcp_opt->tsval;
    }
    tcp_new->check = 0;
    tcp_new->check = csum_ipv6_magic(
    								&(ipv6_new->saddr),
    								&(ipv6_new->daddr), 
    								tcp_new->doff << 2, // 等同于 tcp_new->doff * 4
    								IPPROTO_TCP,
    								csum_partial((char *)tcp_new,tcp_new->doff << 2, 0)
    								);

    //4.设置新的eth头部字段信息
    memcpy(eth_new->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth_new->h_source, skb->dev->dev_addr, ETH_ALEN);
    eth_new->h_proto = htons(ETH_P_IPV6);

    //5.设置新的skb字段信息
    skb_new->dev = skb->dev;
    skb_new->pkt_type = PACKET_OUTGOING;
    skb_new->vlan_tci = 0;
    skb_push(skb_new, ETH_HLEN);

    if (dev_queue_xmit(skb_new) < 0)
    {
    	printk("dev_queue_xmit error\n");
    	kfree_skb(skb_new);	//dev_queue_xmit执行失败要释放skb_new
    	return -1;
    }

    // kfree_skb(skb_new);	//dev_queue_xmit执行成功后不释放skb_new,否则系统宕机
    return 0;
}

static unsigned int ipv6_hook(
	unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	send_tcp_rst_ipv6(skb);
	return NF_ACCEPT;
}

struct nf_hook_ops ipv6_ops = 
{
	.list = {NULL, NULL},
	.hook = ipv6_hook,
    .pf = PF_INET6, 					/* PF_INET:抓取ipv4包 PF_INET6:抓取IPv6数据包 */
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP6_PRI_FILTER + 2
};

static int __init sample_init(void)
{
	nf_register_hook(&ipv6_ops);
	return 0;
}

static void __exit sample_exit(void)
{
	nf_unregister_hook(&ipv6_ops);
}

module_init(sample_init);
module_exit(sample_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("yangqx");
MODULE_DESCRIPTION("sample");
