#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "bootp.h"
#include "color.h"

/** fonction ipv4(...): gestions et analyse de l'entête IP'
 * @param packet: pointeur vers le octet de champ ipv4
 * @param verbose: 1=très concis ; 2=synthétique ; 3=complet
 * @return: 
 */
void ipv4(const unsigned char *packet, int verbose) {
	struct ip *ip = (struct ip*)packet;
	int ip_size = 4*ip->ip_hl;

	void (*next_udp)(const u_char*, int) = NULL;
	void (*next_tcp)(const u_char*, unsigned int, int) = NULL;

	if(verbose == 2 || verbose == 3) 
	{
		printf(FG_LTYELLOW"\t#### IPv4 ####\n"NOCOLOR);

		// ip version
		printf(FG_RED"\tVersion: "NOCOLOR);
		printf(FG_LTWHITE"%d\n"NOCOLOR, ip->ip_v);
		// ihl
		printf(FG_RED"\tIHL: "NOCOLOR);
		printf(FG_LTWHITE"%d (%d bytes)\n"NOCOLOR, ip->ip_hl, ip->ip_hl*4);
		if(verbose == 3)
		{
			printf(FG_RED"\tToS: ");
			printf(FG_LTWHITE"0x%02x\n"NOCOLOR, ip->ip_tos); // TOS
		// length total
		printf(FG_RED"\tTotal length: "NOCOLOR);
		printf(FG_LTWHITE"%d bytes\n"NOCOLOR, ntohs(ip->ip_len));
		}
		if(verbose == 3)
		{
			printf(FG_RED"\tIdentification: "NOCOLOR);
			printf(FG_LTWHITE"0x%04x (%d)\n"NOCOLOR, ntohs(ip->ip_id), ntohs(ip->ip_id));
		}
		// flags
		printf(FG_RED"\tFlags: "NOCOLOR);
		
		if(ntohs(ip->ip_off) & IP_RF) 
			printf(FG_LTWHITE"reserved bit\n"NOCOLOR);
		else if(ntohs(ip->ip_off) & IP_DF)
			printf(FG_LTWHITE"don't fragment\n"NOCOLOR);
		else if(ntohs(ip->ip_off) & IP_MF)
			printf(FG_LTWHITE"more fragment (fragment offset: %d)\n"NOCOLOR, (ntohs(ip->ip_off) & IP_OFFMASK)*8);
		else
			printf(FG_LTWHITE"none set\n"NOCOLOR);

		if(verbose == 3)
		{
			printf(FG_RED"\tTime to live: "NOCOLOR);
			printf(FG_LTWHITE"%d\n"NOCOLOR, ip->ip_ttl); // TTL
			}

		// protocole de la prochaine couche
		printf(FG_RED"\tProtocol: "NOCOLOR);
		switch(ip->ip_p) {
			case 0x01:
				printf(FG_LTWHITE"ICMP "NOCOLOR);
				break;
			case SOL_UDP:
				printf(FG_LTWHITE"UDP "NOCOLOR);
				next_udp = udp;
				break;
			case SOL_TCP:
				printf(FG_LTWHITE"TCP "NOCOLOR);
				next_tcp = tcp;
				break;
			default:
				printf(FG_LTWHITE"Unknown "NOCOLOR);
				break;
		} 
		if(verbose == 3) {
			printf(FG_LTWHITE"(0x%02x)\n"NOCOLOR, ip->ip_p);
			printf(FG_RED"\tChecksum: "NOCOLOR);
			printf(FG_LTWHITE"0x%04x\n"NOCOLOR, ntohs(ip->ip_sum)); // Checksum
		}
		else
			printf("\n");

		printf(FG_RED"\tSource: "NOCOLOR);
		printf(FG_LTWHITE"%s\n"NOCOLOR, inet_ntoa(ip->ip_src)); // @src
		printf(FG_RED"\tDestination: "NOCOLOR);
		printf(FG_LTWHITE"%s\n"NOCOLOR, inet_ntoa(ip->ip_dst)); // @dst
	}
	else { // si verbose 1
		printf(FG_RED" [IPv4] "NOCOLOR);
		printf(FG_RED"@src: "NOCOLOR);
		printf(FG_LTWHITE"%s -> "NOCOLOR,inet_ntoa(ip->ip_src));
		printf(FG_RED"@dst: "NOCOLOR);
		printf(FG_LTWHITE"%s "NOCOLOR,inet_ntoa(ip->ip_dst));

		switch(ip->ip_p) {
			case SOL_UDP:
				next_udp = udp;
				break;
			case SOL_TCP:
				next_tcp = tcp;
				break;
		} 		
	}

	if(next_udp != NULL)
		(*next_udp)(packet + ip_size, verbose);
	else if(next_tcp != NULL)
		(*next_tcp)(packet + ip_size, ntohs(ip->ip_len) - ip_size, verbose);
}


/** fonction ipv6(...): gestions et analyse de l'entête IP'
 * @param packet: pointeur vers le octet de champ ipv6
 * @param verbose: 1=très concis ; 2=synthétique ; 3=complet
 * @return: 
 */
void ipv6(const unsigned char *packet, int verbose) {
	struct ip6_hdr *ip6 = (struct ip6_hdr *) (packet + sizeof(struct ether_header));
	//int ip6_size = (sizeof(struct ether_header));
	
	void (*next_udp)(const u_char*, int) = NULL;
	void (*next_tcp)(const u_char*, unsigned int, int) = NULL;
	
	char * src = (char *) malloc((INET6_ADDRSTRLEN + 1) * sizeof(char));
  char * dst = (char *) malloc((INET6_ADDRSTRLEN + 1) * sizeof(char));
  if (src == NULL )
  {
 	 fprintf(stderr,"error malloc @src\n");
 	 exit(1);
  }
   if (dst == NULL )
   {
 	 fprintf(stderr,"error malloc @dst\n");
 	 exit(1);
  }
  if(inet_ntop(AF_INET6, &ip6->ip6_src, src, INET6_ADDRSTRLEN) == NULL)
  {
		fprintf(stderr,"error inet_ntop\n");
		exit(1);
	}
  if(inet_ntop(AF_INET6, &ip6->ip6_dst, dst, INET6_ADDRSTRLEN) == NULL)
  {
		fprintf(stderr,"error inet_ntop\n");
		exit(1);
	}
  
  switch(verbose)
  {
    case 1:
      printf("[IPv6] @src: %s -> @dst: %s ", src, dst);
      break;
    case 2:
    	printf(FG_LTYELLOW"\t#### IPv6 ####\n"NOCOLOR);
      printf(FG_RED"Version: "NOCOLOR);
      printf(FG_LTWHITE"6\n"NOCOLOR);
      printf(FG_RED"Traffic Class: "NOCOLOR);
      printf(FG_LTWHITE"%u\n"NOCOLOR, (ip6->ip6_flow << 4) >> 20);
      printf(FG_RED"Source: "NOCOLOR);
      printf(FG_LTWHITE"%s\n"NOCOLOR,src);
      printf(FG_RED"Destination: "NOCOLOR);
      printf(FG_LTWHITE"%s\n"NOCOLOR,dst);
      break;
    case 3:
    	printf(FG_LTYELLOW"\t#### IPv6 ####\n"NOCOLOR);
      printf(FG_RED"Version: "NOCOLOR);
      printf(FG_LTWHITE"6\n"NOCOLOR);
      printf(FG_RED"Traffic Class: "NOCOLOR);
      printf(FG_LTWHITE"%u\n"NOCOLOR, (ip6->ip6_flow << 4) >> 20);
      printf(FG_RED"Flow: "NOCOLOR);
      printf(FG_LTWHITE"%u\n"NOCOLOR, ntohs(ip6->ip6_flow << 12));
      printf(FG_RED"Payload length: "NOCOLOR);
      printf(FG_LTWHITE"%u bytes\n"NOCOLOR, ntohs(ip6->ip6_plen));
      printf(FG_RED"Hop limit: "NOCOLOR);
      printf(FG_LTWHITE"%u\n"NOCOLOR, ip6->ip6_hlim);
      printf(FG_RED"Source: "NOCOLOR);
      printf(FG_LTWHITE"%s\n"NOCOLOR,src);
      printf(FG_RED"Destination: "NOCOLOR);
      printf(FG_LTWHITE"%s\n"NOCOLOR,dst);
      break;
    default:
      break;
  }

	if(next_udp != NULL)
		(*next_udp)(packet, verbose);
	else if(next_tcp != NULL)
		(*next_tcp)(packet, ntohs(ip6->ip6_plen) - (sizeof(struct ip6_hdr)), verbose);
		
	free(src);
	free(dst);
}




/** fonction http(...): gestions et analyse des paquets ethernet
 * @param packet: pointeur vers le octet de champ http
 * @param data_size: taille de données
 * @param verbose: 1=très concis ; 2=synthétique ; 3=complet
 * @return: 
 */
void ethernet(const unsigned char *packet, int verbose) 
{
	struct ether_header *ethernet;
	ethernet = (struct ether_header*)(packet);
	int len = sizeof(struct ether_header);


	void (*next_layer)(const unsigned char*, int) = NULL;


	if((verbose == 2 )|| (verbose == 3)) 
	{
		printf(FG_LTYELLOW"\n#### Ethernet ####\n"NOCOLOR);

		printf(FG_MAGENTA"Source: "NOCOLOR);
		printf(FG_LTWHITE"%02x:%02x:%02x:%02x:%02x:%02x\n"NOCOLOR, 
			ethernet->ether_shost[0],
			ethernet->ether_shost[1],
			ethernet->ether_shost[2],
			ethernet->ether_shost[3],
			ethernet->ether_shost[4],
			ethernet->ether_shost[5]);
		
		printf(FG_MAGENTA"Destination: "NOCOLOR);
		printf(FG_LTWHITE"%02x:%02x:%02x:%02x:%02x:%02x\n"NOCOLOR,
			ethernet->ether_dhost[0],
			ethernet->ether_dhost[1],
			ethernet->ether_dhost[2],
			ethernet->ether_dhost[3],
			ethernet->ether_dhost[4],
			ethernet->ether_dhost[5]);
 
		printf(FG_MAGENTA"Type: "NOCOLOR);
		switch(ntohs(ethernet->ether_type)) {
			case ETHERTYPE_IP:
				printf(FG_LTWHITE"IPv4: "NOCOLOR);
				next_layer = ipv4;
				break;
			case ETHERTYPE_IPV6:
				printf(FG_LTWHITE"IPv6 "NOCOLOR);
				next_layer = ipv6;
				break;
			case ETHERTYPE_ARP:
				printf(FG_LTWHITE"ARP "NOCOLOR);
				next_layer = arp;
				break;
			default:
				printf(FG_LTWHITE"Unknown "NOCOLOR);
				break;
		}
		
		if(verbose == 3)
			printf(FG_LTWHITE"(0x%04x)\n"NOCOLOR, ntohs(ethernet->ether_type));
		else
			printf("\n");
	}
	else {
		printf(FG_MAGENTA"@src : "NOCOLOR);
			printf(FG_LTWHITE"%02x:%02x:%02x:%02x:%02x:%02x -> "NOCOLOR, 
			ethernet->ether_shost[0],
			ethernet->ether_shost[1],
			ethernet->ether_shost[2],
			ethernet->ether_shost[3],
			ethernet->ether_shost[4],
			ethernet->ether_shost[5]);

		printf(FG_MAGENTA"@dst : "NOCOLOR);
		printf(FG_LTWHITE"%02x:%02x:%02x:%02x:%02x:%02x"NOCOLOR, 
			ethernet->ether_dhost[0],
			ethernet->ether_dhost[1],
			ethernet->ether_dhost[2],
			ethernet->ether_dhost[3],
			ethernet->ether_dhost[4],
			ethernet->ether_dhost[5]);

		switch(ntohs(ethernet->ether_type)) {
			case ETHERTYPE_IP:
				next_layer = ipv4;
				break;
			case ETHERTYPE_IPV6:
				next_layer = ipv6;
				break;
			case ETHERTYPE_ARP:
				next_layer = arp;
				break;
		}	
	}

	if(next_layer != NULL)
		(*next_layer)(packet + len, verbose);
}
