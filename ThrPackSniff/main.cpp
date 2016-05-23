
//compile with g++ main.cpp -o ThrPackSniff -pthread

//std stuff
#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <string.h>

//thread stuff
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

//network stuff
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

using namespace std;

#define QUEUE_MAX 100
queue<unsigned char*> packets;
mutex packet_lock;
condition_variable packet_cv;

int socketd;
int mtu;

void listenerThread() {
	unsigned char* recvdPack;
	int numRead = 0;

	while(1) {
		recvdPack = new unsigned char[mtu]; //replace with fixed size array - MTU setting
		
		//get from socket
		numRead = recvfrom(socketd, recvdPack, mtu, 0, NULL, NULL);
		
		unique_lock<mutex> lock(packet_lock);
		packet_cv.wait(lock, []{return packets.size() < QUEUE_MAX;});

		packets.push(recvdPack);

		lock.unlock();
		packet_cv.notify_all();
		recvdPack = nullptr;
	}
}

void printerThread() {
	unsigned char* recvdPack;
	struct ether_header* eh;

	while(1) {
		unique_lock<mutex> lock(packet_lock);
		packet_cv.wait(lock, []{return !packets.empty();});

		recvdPack = packets.front();
		packets.pop();

		lock.unlock();
		packet_cv.notify_all();

		//print packet
		eh = (struct ether_header*) recvdPack;
		printf("Src: %02x:%02x:%02x:%02x:%02x:%02x\nDst: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
			eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
			eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
			eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
			eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
		
		delete[] recvdPack;
		recvdPack = nullptr;
	}
}

int main(int argc, char** argv) {
	//set up socket
	if(argc != 2) {
		printf("Usage: ThrPackSniff <iname>\nUse ^C to quit\n");
		return 1;
	}
	char* if_name = argv[1];

	socketd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if(socketd == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}

	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if(if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		printf("Interface name is too long.\n");
		return 1;
	}
	if(ioctl(socketd, SIOCGIFINDEX, &ifr) == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}
	int ifindex = ifr.ifr_ifindex;
	if(ioctl(socketd, SIOCGIFMTU, &ifr) == -1) {
		printf("%s\n", strerror(errno));
		return 1;
	}
	mtu = ifr.ifr_mtu;
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

	//start threads
	thread printer (printerThread);
	thread listener (listenerThread);

	printer.join();
	listener.join();

	return 0;
}
