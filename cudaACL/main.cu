
#include <cuda.h>

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <netinet/ip.h>

enum protocolType {
	IP, //both
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


int eval(struct in_addr srcIP, struct in_addr dstIP, enum protocolType proto, uint16_t port, struct aclRule* rules, int nRules) { //bool
	for(int i = 0; i < nRules; i++) {
		//if it doesn't apply ignore
		if((srcIP & rules[i].src_mask) != rules[i].src_network || (dstIP & rules[i].dst_mask) != rules[i].dst_network
				|| proto == IP || proto != rules[i].proto || port != rules[i].port) {
			continue;
		}
		
		//the rule applies, allow or deny
		return rules[i].allow;
	}

	//implicit deny all
	return 0;
}

//<<<1, n, 2*n>>>
__global__
void eval_kernel(struct in_addr srcIP, struct in_addr dstIP, enum protocolType proto, uint16_t port, struct aclRule* rules, int nRules, uint8_t* out) { //bool
	extern __shared__ uint8_t buf[];
	uint8_t* apply = &buf[0];
	uint8_t* pass = &buf[nRules];

	int tid = blockDim.x * blockIdx.x + threadIdx.x;

	if(tid > nRules) {
		return 1; //true
	}

	apply[tid] = ((srcIP & rules[tid].src_mask) != rules[tid].src_network || (dstIP & rules[tid].dst_mask) != rules[tid].dst_network
			|| proto == IP || proto != rules[tid].proto || port != rules[tid].port);
	pass[tid] = rules[tid];
	
	syncThreads();

	//reduce 
	for(unsigned int i = blockDim.x/2; i > 0; i >>= 1) {
		if(apply[tid+i]) {
			pass[tid] &= pass[tid+1];
		} else {
			pass[tid+i] = 1;
		}

		syncThreads();
	}

	&out = pass[0];
}

int main(int argc, char** argv) {

	return 0;
}
