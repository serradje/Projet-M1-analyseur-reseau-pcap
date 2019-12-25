#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "bootp.h"
#include "color.h"


// gestion des paquets ARP
void arp(const unsigned char *packet, int verbose) {
	struct arphdr *arp = (struct arphdr*)packet;
	int arp_size = sizeof(struct arphdr);
	struct _arpaddr *arpaddr = (struct _arpaddr*)(packet + arp_size);

	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t#### ARP ####\n"NOCOLOR);
		printf(FG_RED"\tHardware type: "NOCOLOR);
		switch(ntohs(arp->ar_hrd)) {
			case ARPHRD_ETHER:
				printf(FG_LTWHITE"Ethernet"NOCOLOR);
				break;
			default:
				printf(FG_LTWHITE"Unknown"NOCOLOR);
				break;
		}
		if(verbose == 3) 
			printf(FG_LTWHITE" (0x%04x)\n"NOCOLOR, ntohs(arp->ar_hrd));
		else
			printf("\n");

		/* protocole */ 
		printf(FG_RED"\tProtocol type: "NOCOLOR);
		switch(ntohs(arp->ar_pro)) {
			case ETHERTYPE_IP:
				printf(FG_LTWHITE"IPv4"NOCOLOR);
				break;
			case ETHERTYPE_IPV6:
				printf(FG_LTWHITE"IPv6"NOCOLOR);
				break;
			default:
				printf(FG_LTWHITE"Unknown"NOCOLOR);
				break;
		}
		if(verbose == 3) 
			printf(FG_LTWHITE" (0x%04x)\n"NOCOLOR, ntohs(arp->ar_pro));
		else
			printf("\n");
	}

	/*length address*/
	if(verbose == 3) {
		printf(FG_RED"\tHardware Address Length: "NOCOLOR);
		printf(FG_LTWHITE"%d bytes\n"NOCOLOR, arp->ar_hln);
		printf(FG_RED"\tProtocol Address Length: "NOCOLOR);
		printf(FG_LTWHITE"%d bytes\n"NOCOLOR, arp->ar_pln);
	}

	/*ARP request type*/
	if(verbose == 2 || verbose == 3)
	{
		printf(FG_RED"\tOperation : "NOCOLOR);
		switch(ntohs(arp->ar_op)) {
			case ARPOP_REQUEST:
				printf(FG_LTWHITE"ARP Request\n"NOCOLOR);
				break;
			case ARPOP_REPLY:
				printf(FG_LTWHITE"ARP Reply\n"NOCOLOR);
				break;
			case ARPOP_RREQUEST:
				printf(FG_LTWHITE"RARP Request\n"NOCOLOR);
				break;
			case ARPOP_RREPLY:
				printf(FG_LTWHITE"RARP Reply\n"NOCOLOR);
				break;
			case ARPOP_InREQUEST:
				printf(FG_LTWHITE"InARP Request\n"NOCOLOR);
				break;
			case ARPOP_InREPLY:
				printf(FG_LTWHITE"InARP Reply\n"NOCOLOR);
				break;
			case ARPOP_NAK:
				printf(FG_LTWHITE"ARP NAK\n"NOCOLOR);
				break;
			default:
				printf(FG_LTWHITE"Unknown\n"NOCOLOR);
				break;
		}

		printf(FG_RED"\tSender hardware address: "NOCOLOR);
		printf(FG_LTWHITE"%02x:%02x:%02x:%02x:%02x:%02x\n"NOCOLOR, 
			arpaddr->ar_sha[0],
			arpaddr->ar_sha[1],		
			arpaddr->ar_sha[2],
			arpaddr->ar_sha[3],
			arpaddr->ar_sha[4],
			arpaddr->ar_sha[5]
		);
		printf(FG_RED"\tSender protocol address: "NOCOLOR);
		printf(FG_LTWHITE"%d.%d.%d.%d\n"NOCOLOR, 
			arpaddr->ar_spa[0],
			arpaddr->ar_spa[1],
			arpaddr->ar_spa[2],
			arpaddr->ar_spa[3]
		);
		printf(FG_RED"\tTarget hardware address: ");
		printf(FG_LTWHITE"%02x:%02x:%02x:%02x:%02x:%02x\n"NOCOLOR, 
			arpaddr->ar_tha[0],
			arpaddr->ar_tha[1],		
			arpaddr->ar_tha[2],
			arpaddr->ar_tha[3],
			arpaddr->ar_tha[4],
			arpaddr->ar_tha[5]
		);
		printf(FG_RED"\tSender protocol address: ");
		printf(FG_LTWHITE"%d.%d.%d.%d\n"NOCOLOR, 
			arpaddr->ar_tpa[0],
			arpaddr->ar_tpa[1],
			arpaddr->ar_tpa[2],
			arpaddr->ar_tpa[3]
		);
	}
	else {
		switch(ntohs(arp->ar_op)) {
			case ARPOP_REQUEST:
				printf(FG_RED"[ARP] "NOCOLOR);
				printf(FG_LTWHITE"Request"NOCOLOR);
				break;
			case ARPOP_REPLY:
				printf(FG_RED"[ARP] "NOCOLOR);
				printf(FG_LTWHITE" Reply"NOCOLOR);
				break;
			case ARPOP_RREQUEST:
				printf(FG_RED"[RARP] "NOCOLOR);
				printf(FG_LTWHITE"Request"NOCOLOR);
				break;
			case ARPOP_RREPLY:
				printf(FG_RED"[RARP] "NOCOLOR);
				printf(FG_LTWHITE"Reply"NOCOLOR);
				break;
			case ARPOP_InREQUEST:
				printf(FG_RED"[InARP] "NOCOLOR);
				printf(FG_LTWHITE"Request"NOCOLOR);
				break;
			case ARPOP_InREPLY:
				printf(FG_RED"[InARP] "NOCOLOR);
				printf(FG_LTWHITE"Reply"NOCOLOR);
				break;
			case ARPOP_NAK:
				printf(FG_RED"[ARP] "NOCOLOR);
				printf(FG_LTWHITE"NAK"NOCOLOR);
				break;
			default:
				printf(FG_RED"[ARP] "NOCOLOR);
				printf(FG_LTWHITE"Unknown"NOCOLOR);
				break;
		}		
	}

}












