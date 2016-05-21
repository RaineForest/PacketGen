
//std stuff
#include <cstdio>
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

queue<struct msghdr*> packets;
mutex packet_lock;
condition_variable packet_cv;

void printerThread() {
	struct msghdr* recvdPack;

	unique_lock<mutex> lock(packet_lock);
	while(true) {
		while(packets.empty()) {packet_cv.wait(lock)};

		recvdPack = packets.front();
		packets.pop();

		lock.unlock();
		packet_cv.notify_all(lock);

		//print packet
		
		delete recvdPack;
		recvdPack = nullptr;
	}
}

void listenerThread() {
	unique_lock<mutex> lock(packet_lock);
	struct msghdr* recvdPack;

	while(true) {
		recvdPack = new struct msghdr; //replace with fixed size array - MTU setting
		
		//resvmsg
		
		packet_cv.wait(lock);

		packets.push(recvdPack);

		lock.unlock();
		packet_cv.notify_all(lock);
		recvdPack = nullptr;
	}
}

int main(int argc, char** argv) {
	thread printer (printerThread);
	thread listener (listenerThread);

	printer.join();
	listener.join();

	return 0;
}
