
#include <cuda.h>

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <netinet/ip.h>

enum protocolType {
	IP,
	TCP,
	UDP
};

struct aclRule {
	uint8_t allow;
	struct in_addr src_network;
	struct in_addr src_mask;
	struct in_addr dst_network;
	struct in_addr dst_mask;
	enum protocolType proto;
	uint16_t port;
};

__global__
int kernel(struct in_addr srcIP, struct in_addr dstIP, enum protocolType proto, uint16_t port, struct aclRule* rules, int nRules) { //bool
	int tid = blockDim.x * blockIdx.x + threadIdx.x;
	if(tid > nRules) {
		return 1; //true
	}


	//reduce 
}

int main(int argc, char** argv) {

	return 0;
}
