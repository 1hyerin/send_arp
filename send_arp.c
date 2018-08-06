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

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPPROTO_TCP 0x06
#define IPPROTO_UDP 0x11
#define IPPROTO_ICMP 0x01

#define ETH_ALEN 6
#define ETH_SIZE 14
#define ARP_HWADD 6
#define ARP_IPLEN 4

void usage() {
	printf("Usage: send_arp <interface> <sender ip> <target ip>\n");
}

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

/*공격자 맥 정보를 알아내는 방법은 코드 참고 -- 링크: http://egloos.zum.com/kangfeel38/v/4273426 */
int GetSvrMacAddress() {
	int nSD; // Socket descriptor
	struct ifreq *ifr; // Interface request
	struct ifconf ifc;
	int i, numif;

	memset(&ifc, 0, sizeof(ifc));
	ifc.ifc_ifcu.ifcu_req = NULL;
	ifc.ifc_len = 0;

 	// Create a socket that we can use for all of our ioctls
 	nSD = socket( PF_INET, SOCK_DGRAM, 0 );
 	if ( nSD < 0 )  return 0;
 	if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
 	if ((ifr = (ifreq*)  malloc(ifc.ifc_len)) == NULL) {
 		return 0;
 	}
 	else {
 		ifc.ifc_ifcu.ifcu_req = ifr;
 		if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0) {
 			return 0;
 		}
 		numif = ifc.ifc_len / sizeof(struct ifreq);
 		for (i = 0; i < numif; i++) {
 			struct ifreq *r = &ifr[i];
 			struct sockaddr_in *sin = (struct sockaddr_in *)&r->ifr_addr;
 			if (!strcmp(r->ifr_name, "lo")) continue; // skip loopback interface
 			if(ioctl(nSD, SIOCGIFHWADDR, r) < 0) return 0;
 			char macaddr[100];
 			sprintf(macaddr, "[%s] %02X:%02X:%02X:%02X:%02X:%02X",
 				r->ifr_name,
 				(uint8_t)r->ifr_hwaddr.sa_data[0],
 				(uint8_t)r->ifr_hwaddr.sa_data[1],
 				(uint8_t)r->ifr_hwaddr.sa_data[2],
 				(uint8_t)r->ifr_hwaddr.sa_data[3],
 				(uint8_t)r->ifr_hwaddr.sa_data[4],
 				(uint8_t)r->ifr_hwaddr.sa_data[5]);
 			return 0;
 		}
 	}
 	close(nSD);
 	free(ifr);
 	return 1;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return 0;
    }
}