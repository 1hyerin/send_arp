/** BoB 7기 원혜린 */
/** 제출 일자: 2018년 08월 06일 */
/** params sample: ./send_arp any 192.168.10.1 192.168.10.2 */

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPPROTO_TCP 0x06
#define IPPROTO_UDP 0x11
#define IPPROTO_ICMP 0x01

#define ETH_ALEN 6
#define ETH_SIZE 14
#define ARP_HWADD 6
#define ARP_IPLEN 4
#define ARP_PADD 18

#define CHK_LEN 6

#define INPUT_LENGTH 100

uint8_t * broad_eth_cast = "\xff\xff\xff\xff\xff\xff";
uint8_t	null_get_eth[] = {0, 0, 0, 0, 0, 0};

void usage() {
	printf("Usage: send_arp <interface> <sender ip> <target ip>\n");
}




/* ==========================WHOLE HEADER=============================== */
struct ethhdr {
	uint8_t ethdest[ETH_ALEN]; /* Destination MAC Address */
	uint8_t ethsrc[ETH_ALEN]; /* Source MAC Address */
	uint16_t e_type;
};

/** ARP Header */
#define ARP_REQUEST 1 /* ARP Request */ 
#define ARP_REPLY 2 /* ARP Reply */ 
struct arphdr {
	uint16_t htype; /* Hardware Type */ 
    uint16_t ptype; /* Protocol Type */ 
    uint8_t hlen; /* Hardware Address Length */ 
    uint8_t plen; /* Protocol Address Length */ 
    uint16_t oper; /* Operation Code */ 
    uint8_t sha[ARP_HWADD]; /* Sender hardware address */ 
    uint8_t spa[ARP_IPLEN]; /* Sender IP address */ 
    uint8_t tha[ARP_HWADD]; /* Target hardware address */ 
    uint8_t tpa[ARP_IPLEN]; /* Target IP address */ 
};

struct whole_hdr {
	uint8_t w_ethdest[ETH_ALEN]; /* Destination MAC Address */
	uint8_t w_ethsrc[ETH_ALEN]; /* Source MAC Address */
	uint16_t w_e_type;

	uint16_t w_htype; /* Hardware Type */ 
    uint16_t w_ptype; /* Protocol Type */ 
    uint8_t w_hlen; /* Hardware Address Length */ 
    uint8_t w_plen; /* Protocol Address Length */ 
    uint16_t w_oper; /* Operation Code */ 
    uint8_t w_sha[ARP_HWADD]; /* Sender hardware address */ 
    uint8_t w_spa[ARP_IPLEN]; /* Sender IP address */ 
    uint8_t w_tha[ARP_HWADD]; /* Target hardware address */ 
    uint8_t w_tpa[ARP_IPLEN]; /* Target IP address */ 
    uint8_t w_padding[ARP_PADD];
}

//sending: codes are at the below------------------------------------------
whole_hdr * getMAC (pcap_t * handle, uint8_t * attackerMAC, uint8_t * tIP);

/* ==================================================================== */




/* ============================ NEEDED ================================ */

/* --------------1. Checking the right input of the interface is needed!----------------- */
int getMacAddr(char * intfInput, char * buf) {
	char intfName[INPUT_LENGTH];
	char getAddrFile[strlen("/sys/class/net//address")+INPUT_LENGTH]; //Knowing about the addr: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net
	//To put the right things, we should give the arr size like length and input length, and input means like argv

	FILE *gettingFiles;
	strncpy(intfName, intfInput, INPUT_LENGTH-1); //char *strncpy(char *string1, const char *string2, size_t count);
	intfName[INPUT_LENGTH - 1] = '\0'; //We should put null byte first!

	//We should get mac addr from here
	sprintf(getAddrFile, "/sys/class/net/%s/address", intfName); //int sprintf(char *buffer, const char *format-string, argument-list);
	if (gettingFiles = fopen(getAddrFile, "r")) {
		fscanf(gettingFiles, "%s", buf);
		fclose(gettingFiles);
	} else {
		printf("Wrong Input\n\n");
		return -1;
	} //checking the wrong input
	return 0;
}
/* ---------------------------------------------------------------------------------------- */

/* --------------2. arp request----------------- */
void arpRequest(pcap_t* handle, char* attackerMAC, uint8_t* tIPget) {
	whole_hdr pktReq;
	pktReq.w_e_type = ETHERTYPE_ARP;

	memcpy(pktReq.w_ethsrc, attackerMAC, 6);
	memcpy(pktReq.w_ethdest, broad_eth_cast, 6);
	memcpy(pktReq.w_sha, attackerMAC, 6);
	memcpy(pktReq.w_spa, "\xc0\xa8\x05\x97", 4);

	memcpy(pktReq.w_tha, null_get_eth, 6);
	memcpy(pktReq.arp_dstip, tIPget, 4);
	memset(pktReq.w_padding, 0, ARP_PADD);

	pktReq.w_oper = 0x0100;
	pktReq.w_htype = 0x0100;
	pktReq.w_ptype = ETHERTYPE_IP;
	pktReq.w_hlen = 6;
	pktReq.w_plen = 4;
}
/* --------------------------------------------- */

/* ------------- 3.arp reply --------------------*/
void arpReply(pcap_t * handle, uint8_t * ownEthernet, uint8_t * destin_eth, uint8_t * destin_ip)
{
	whole_hdr packet;
	packet.w_e_type = ETHERTYPE_ARP;

	memcpy(packet.w_ethdest, destin_eth, 6);
	memcpy(packet.w_ethsrc, ownEthernet, 6);	
	memcpy(packet.w_sha, ownEthernet, 6);
	memcpy(packet.w_spa, "\xc0\xa8\x05\x97", 4);

	memcpy(packet.w_tha, destin_eth, 6);
	memcpy(packet.arp_dstip, destin_ip, 4);
	memset(packet.w_padding, 0, 18);

	packet.w_oper = 0x0200;
	packet.w_htype = 0x0100;
	packet.w_ptype = ETHERTYPE_IP;
	packet.w_hlen = 6;
	packet.w_plen = 4;
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return 0;
    }
}


whole_hdr *getMAC(pcap_t *handle, uint8_t* attackerMAC, uint8_t* tIP) {
	whole_hdr * arpSend;
	uint32_t netSniff;
	const uint8_t *packet;
	packet = pcap_next(handle, &pcPktHdr);
	char filtering[] = "arp";

	struct pcap_pkthdr pcPktHdr;
	/* struct pcap_pkthdr {
    struct timeval ts; //time stamp
    bpf_u_int32 caplen; //length of portion present 
    bpf_u_int32 len; //length this packet (off wire) 
	};*/

	struct bpf_program bpfPro;
	//filtering structure! It can compile, and use it!

	arpRequest(handle, attackerMAC, tIP); //sending the req
	if((pcap_compile(handle, &bpfPro, filtering, 0, netSniff))==-1) { //int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
		return 1;
	}
	if((pcap_setfilter(handle, &bpfPro))==-1) { //int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
		return 1;
	} //check the filtering errors

	//pck--->grab!

	arpSend = (struct whole_hdr *)(packet);
	for(int i=0; i<CHK_LEN; i++) {
		printf("%02x:", arpSend->w_sha[i]);
	}
	
	return arpSend -> w_sha;
}
