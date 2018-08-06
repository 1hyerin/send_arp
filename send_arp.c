/** BoB 7기 원혜린 */
/** 제출 일자: 2018년 08월 06일 */
/** params sample: ./send_arp any 192.168.10.1 192.168.10.2 */

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPPROTO_TCP 0x06
#define IPPROTO_UDP 0x11
#define IPPROTO_ICMP 0x01

#define ETH_ALEN 6
#define ETH_SIZE 14

void usage() {
	printf("Usage: send_arp <interface> <sender ip> <target ip>\n");
}

struct ethhdr {
	uint8_t ethdest[ETH_ALEN];	// Destination MAC Address
	uint8_t ethsrc[ETH_ALEN];	// Source MAC Address
	uint16_t e_type;
};

struct arp_hdr {
    uint16_t hwtype;
    uint16_t protype;
    uint32_t hwsize;
    uint32_t prosize;
    uint16_t opcode;
    uint32_t data;
};