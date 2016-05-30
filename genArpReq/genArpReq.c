#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

//we gon' send ARP today boi (yes i wrote this at 3:30 AM, but mostly copied from microHOWTO.info)
//NOTE: needs root priv
int main(int argc, char** argv) {
	if(argc != 3) {
		printf("Usage: genArpReq <iname> <target ip>\n");
		return 1;
	}
	char* if_name = argv[1];

	//create the socket
	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if(fd == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}

	//deterimine interface index
	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if(if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		printf("interface name is too long\n");
		return 1;
	}
	if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		printf("%s", strerror(errno));
		return 1;
	}
	int ifindex = ifr.ifr_ifindex;

	//make the destination addr
	const unsigned char ether_broadcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	struct sockaddr_ll addr = {0};
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifindex;
	addr.sll_halen = ETHER_ADDR_LEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

	//send that shit
	struct ether_arp req;
	req.arp_hrd=htons(ARPHRD_ETHER);
	req.arp_pro=htons(ETH_P_IP);
	req.arp_hln=ETHER_ADDR_LEN;
	req.arp_pln=sizeof(in_addr_t);
	req.arp_op=htons(ARPOP_REQUEST);
	memset(&req.arp_tha, 0, sizeof(req.arp_tha));
	memcpy(&req.arp_tha, &ether_broadcast_addr, sizeof(req.arp_tha));

	const char* target_ip_string = argv[2]; //target addr
	struct in_addr target_ip_addr = {0};
	if(!inet_aton(target_ip_string, &target_ip_addr)) {
		printf("%s is not a vaild IP address\n", target_ip_string);
		return 1;
	}
	memcpy(&req.arp_tpa, &target_ip_addr.s_addr, sizeof(req.arp_tpa));

	//get src MAC
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}
	if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		printf("not an Ethernet interface\n");
		return 1;
	}
	const unsigned char* src_mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;

	memcpy(&req.arp_sha, src_mac, sizeof(req.arp_sha));

	//get our ip addr
	struct in_addr src_ip_addr = {0};
	if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}
	src_ip_addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;

	memcpy(&req.arp_spa, &src_ip_addr.s_addr, sizeof(req.arp_spa));

	//actually send that shit
	struct iovec iov[1];
	iov[0].iov_base = &req;
	iov[0].iov_len = sizeof(req);
	
	struct msghdr message;
	message.msg_name = &addr;
	message.msg_namelen = sizeof(addr);
	message.msg_iov = iov;
	message.msg_iovlen = 1;
	message.msg_control = 0;
	message.msg_controllen = 0;

	if(sendmsg(fd, &message, 0) == -1) {
		printf("%s", strerror(errno));
		return 1;
	}
	
	return 0;
}
