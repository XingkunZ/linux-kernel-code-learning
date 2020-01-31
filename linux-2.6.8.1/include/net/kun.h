// #ifndef _KUN_H
// #define _KUN_H

extern struct proto_ops kun_sk_ops;
extern struct net_proto_family kun_family_ops;

extern int  kun_create(struct socket * sock, int protocol);
extern int  kun_sendmsg();
extern int  kun_recvmsg();
extern int  kun_release(struct socket *sock);
extern int  kun_sock_init(void);
extern void kun_sock_exit(void);