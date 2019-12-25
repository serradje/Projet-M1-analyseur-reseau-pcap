#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

#include "bootp.h"
#include "color.h"



// gestion des paquets udp
void udp(const unsigned char *packet, int verbose) {
	struct udphdr* udp = (struct udphdr*)(packet);
	int udp_size = sizeof(struct udphdr);

	void (*next_layer)(const u_char*, int, int) = NULL;

	// si verbose 2 et 3
	if(verbose == 2 || verbose == 3) 
	{
		printf(FG_LTYELLOW"\t\t#### UDP ####\n"NOCOLOR);
		printf(FG_GREEN"\t\tSource port:"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR, ntohs(udp->uh_sport));
	}
	switch(ntohs(udp->uh_sport)) {
		case 53:
			next_layer = dns;
			break;
		case 67|68:
			next_layer = bootp;
			break;
	}
	if(verbose == 2 || verbose == 3)
	{
		printf(FG_GREEN"\t\tDestination port:"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR, ntohs(udp->uh_dport));
	}
	if(next_layer == NULL) 
	{
		switch(ntohs(udp->uh_dport)) {
			case 53:
				next_layer = dns;
				break;
			case 67:
				next_layer = bootp;
				break;
			case 68:
				next_layer = bootp;
				break;
		}
	}
	if(verbose == 2 || verbose == 3)
	{
		printf(FG_GREEN"\t\tLength:"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR, ntohs(udp->uh_ulen));
	}
	if(verbose == 3)
	{
		printf(FG_GREEN"\t\tChecksum:"NOCOLOR);
		printf(FG_LTWHITE" 0x%04x\n"NOCOLOR, ntohs(udp->uh_sum));
	}

	// si verbose 1
	if(verbose == 1)
	{
		printf(FG_BLUE"\n\t\t\t\t\t\t\t\t   |_[UDP] Source port: "NOCOLOR);
		printf(FG_LTWHITE"%d -> "NOCOLOR,ntohs(udp->uh_sport));
			printf(FG_BLUE" Destination port: "NOCOLOR);
		printf(FG_LTWHITE"%d\n"NOCOLOR,ntohs(udp->uh_dport));
	}
	if(next_layer != NULL && (int)(ntohs(udp->uh_ulen) - udp_size) > 0)
		(*next_layer)(packet + udp_size, (int)(ntohs(udp->uh_ulen) - udp_size), verbose);
}


// gestion des paquets tcp
void tcp(const u_char *packet, unsigned int tcp_size, int verbose) {
	struct tcphdr* tcp = (struct tcphdr*)(packet);
	int tcphdr_size = tcp->th_off*4;

	void (*next_layer)(const u_char*, int, int) = NULL;

	if(verbose == 2 || verbose == 3) {

		printf(FG_LTYELLOW"\t\t#### TCP ####\n"NOCOLOR);
		printf(FG_GREEN"\t\tSource port:"NOCOLOR); // port source 
		printf(FG_LTWHITE" %d\n", ntohs(tcp->th_sport)); 
	}
	switch(ntohs(tcp->th_sport)) 
	{
		case 80:
			next_layer = http;
			break;
		case 23:
			next_layer = telnet;
			break;
		case 25:
			next_layer = smtp;
			break;
		case 110:
			next_layer = pop;
			break;
		case 143:
			next_layer = imap;
			break;
		case 20:
			next_layer = ftp;
			break;
		case 21:
			next_layer = ftp;
			break;
	}
	if(verbose == 2 || verbose == 3)
	{
		printf(FG_GREEN"\t\tDestination port:"NOCOLOR); // port destination
		printf(FG_LTWHITE" %d\n", ntohs(tcp->th_dport)); 
	}
	if(next_layer == NULL) 
	{
		switch(ntohs(tcp->th_dport)) {
			case 80:
				next_layer = http;
				break;
			case 23:
				next_layer = telnet;
				break;
			case 25:
				next_layer = smtp;
				break;
			case 110:
				next_layer = pop;
				break;
			case 143:
				next_layer = imap;
				break;
			case 20:
				next_layer = ftp;
				break;
			case 21:
				next_layer = ftp;
				break;
		}		
	}

	if(verbose == 2 || verbose == 3)
	 {
		printf(FG_GREEN"\t\tSequence number:"NOCOLOR);
		printf(FG_LTWHITE" %u (0x%x)\n"NOCOLOR, ntohs(tcp->th_seq), ntohl(tcp->th_seq));
		
		printf(FG_GREEN"\t\tAcknowledgment number:"NOCOLOR);
		printf(FG_LTWHITE" %u (0x%x)\n"NOCOLOR, ntohs(tcp->th_ack), ntohl(tcp->th_ack));
		
		printf(FG_GREEN"\t\tHeader length:"NOCOLOR);
		printf(FG_LTWHITE" %d bytes\n"NOCOLOR, tcphdr_size);
	}

	if(verbose == 3)
	{
		printf(FG_GREEN"\t\tFlags: "NOCOLOR);
		printf(FG_LTWHITE"(0x%02x) "NOCOLOR, tcp->th_flags);
	}
	else if(verbose == 2)
		printf(FG_GREEN"\t\tFlags: "NOCOLOR);

	if(verbose == 2 || verbose == 3) 
	{
		if(TH_FIN & tcp->th_flags)
			printf(FG_LTWHITE" FIN"NOCOLOR);
		if(TH_SYN & tcp->th_flags)
			printf(FG_LTWHITE" SYN"NOCOLOR);
		if(TH_RST & tcp->th_flags)
			printf(FG_LTWHITE" RST"NOCOLOR);
		if(TH_PUSH & tcp->th_flags)
			printf(FG_LTWHITE" PSH"NOCOLOR);
		if(TH_ACK & tcp->th_flags)
			printf(FG_LTWHITE" ACK"NOCOLOR);
		if(TH_URG & tcp->th_flags)
			printf(FG_LTWHITE" URG"NOCOLOR);
	}
	printf("\n");
	if(verbose == 3) 
	{
		printf(FG_GREEN"\t\tWindow:"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR, ntohs(tcp->th_win));
		
		printf(FG_GREEN"\t\tChecksum:"NOCOLOR);
		printf(FG_LTWHITE" 0x%04x\n"NOCOLOR, ntohs(tcp->th_sum));
		
		printf(FG_GREEN"\t\tUrgent Pointer:"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR,ntohs(tcp->th_urp));
	}
	int i, j, tmp;
	if(tcp_size > sizeof(struct tcphdr)) {
		if(verbose == 3) {
			printf(FG_GREEN"\t\t[Options]:\n"NOCOLOR);
			for(i=sizeof(struct tcphdr); i<tcphdr_size && packet[i] != 0x00; i++) 
			{
				switch(packet[i]) {
					case 1:
						printf(FG_BLUE"\t\t - NOP\n" NOCOLOR);
						break;
					case 2:
						printf(FG_BLUE"\t\t - Type:"NOCOLOR);
						printf(FG_LTWHITE" Maximum Segment Size (%d)\n"NOCOLOR, packet[i]);
						
						printf(FG_BLUE"\t\t - Length:"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, packet[i+1]);
						
						tmp = packet[i+2]<<8 | packet[i+3];
						printf(FG_BLUE"\t\t - MSS Value:"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, tmp);
						i += (int)packet[i+1]-1;
						break;
					case 3:
						printf(FG_BLUE"\t\t - Type:"NOCOLOR);
						printf(FG_LTWHITE" Windows Scale (%d)\n"NOCOLOR, packet[i]);
						
						printf(FG_BLUE"\t\t - Length:"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, packet[i+1]);
						
						printf(FG_BLUE"\t\t - Windows Scale Value:"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, packet[i+2]);
						
						i += (int)packet[i+1]-1;
						break;
					case 4:
						printf(FG_BLUE"\t\t - Type:"NOCOLOR);
						printf(FG_LTWHITE" SACK permited\n"NOCOLOR);
						
						printf(FG_BLUE"\t\t   Length:"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, packet[i+1]);
						
						i += (int)packet[i+1]-1;
						break;
					case 8:
						printf(FG_BLUE"\t\t - Type:"NOCOLOR);
						printf(FG_LTWHITE" Time Stamp Option(%d)\n"NOCOLOR, packet[i]);
						
						printf(FG_BLUE"\t\t - Length:"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, packet[i+1]);
						
						tmp = packet[i+2] << 24 | packet[i+3] << 16 | packet[i+4] << 8 | packet[i+5];
						printf(FG_BLUE"\t\t - Timestamp Value:"NOCOLOR);
						printf(FG_LTWHITE" %u\n"NOCOLOR, tmp);
						
						tmp = packet[i+6] << 24 | packet[i+7] << 16 | packet[i+8] << 8 | packet[i+9];
						printf(FG_BLUE"\t\t - Timestamp echo reply:"NOCOLOR);
						printf(FG_LTWHITE" %u\n"NOCOLOR, tmp);
						
						i += (int)packet[i+1]-1;	
						break;
					default:
						printf(FG_BLUE"\t\t - Type:"NOCOLOR);
						printf(FG_LTWHITE" unknown (%d)\n"NOCOLOR, packet[i]);
						
						printf(FG_BLUE"\t\t - Length"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, packet[i+1]);
						if((int)packet[i+1]>2) {
							printf(FG_BLUE"\t\t - Value: 0x"NOCOLOR);
							for(j=2; j<(int)packet[i+1]; j++) {
								printf(FG_LTWHITE"%02x"NOCOLOR, packet[j+i]);
							}
							printf("\n");
						}
						i += (int)packet[i+1]-1;
						break;
				}
			}
		}
		else if(verbose == 2) {
			printf(FG_GREEN"\t\t[Options]:"NOCOLOR);
			printf(FG_LTWHITE" %ld bytes\n"NOCOLOR, tcp_size - sizeof(struct tcphdr));
		}
	}

	// si verbose 1
	if(verbose == 1) {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t     |_[TCP] Source port: "NOCOLOR);
		printf(FG_LTWHITE"%d -> "NOCOLOR,ntohs(tcp->th_sport));
		printf(FG_BLUE" Destination port: "NOCOLOR);
		printf(FG_LTWHITE"%d "NOCOLOR,ntohs(tcp->th_dport));
		printf(FG_BLUE"\n\t\t\t\t\t\t\t\t           |_[Flags] "NOCOLOR);
		if(TH_FIN & tcp->th_flags)
			printf(FG_LTWHITE"FIN "NOCOLOR);
		if(TH_SYN & tcp->th_flags)
			printf(FG_LTWHITE"SYN "NOCOLOR);
		if(TH_RST & tcp->th_flags)
			printf(FG_LTWHITE"RST "NOCOLOR);
		if(TH_PUSH & tcp->th_flags)
			printf(FG_LTWHITE"PSH "NOCOLOR);
		if(TH_ACK & tcp->th_flags)
			printf(FG_LTWHITE"ACK "NOCOLOR);
		if(TH_URG & tcp->th_flags)
			printf(FG_LTWHITE"URG "NOCOLOR);
		
	}
		printf("\n");
	if(next_layer != NULL && (tcp_size - tcphdr_size) > 0)
		(*next_layer)(packet + tcphdr_size, tcp_size - tcphdr_size, verbose);

}
