#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>

#include "bootp.h"
#include "color.h"


// gestion des paquets bootp / dhcp

void bootp(const unsigned char *packet, int data_size, int verbose) {
	struct bootphdr *bootp;
	bootp = (struct bootphdr*)packet;
	int i;

	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t\t\t#### BOOTP ####\n"NOCOLOR);
		printf(FG_BLUE"\t\t\tMessage type : "NOCOLOR);
		switch(bootp->bp_op) {
			case 1:
				printf(FG_LTWHITE"Request\n"NOCOLOR);
				break;
			case 2:
				printf(FG_LTWHITE"Reply\n"NOCOLOR);
				break;
			default:
				printf(FG_LTWHITE"Unknown\n"NOCOLOR);
				break;
		}
	}

	if(verbose == 3) {
		printf(FG_BLUE"\t\t\tHardware type : "NOCOLOR);
		switch(bootp->bp_htype) {
			case 1:
				printf(FG_LTWHITE"Ethernet\n"NOCOLOR);
				break;
			case 6:
				printf(FG_LTWHITE"IEEE 802\n"NOCOLOR);
				break;
			case 18:
				printf(FG_LTWHITE"Fibre Channel\n"NOCOLOR);
				break;
			case 20:
				printf(FG_LTWHITE"Serial Line\n"NOCOLOR);
				break;
			default:
				printf(FG_LTWHITE"Unknown\n"NOCOLOR);
				break;
		}
		printf(FG_BLUE"\t\t\tHardware Address Length :"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR, bootp->bp_hlen);
		
		printf(FG_BLUE"\t\t\tHops :"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR, bootp->bp_hops);
		
		printf(FG_BLUE"\t\t\tTransaction ID :"NOCOLOR);
		printf(FG_LTWHITE" 0x%08x\n"NOCOLOR, ntohl(bootp->bp_xid));
		
		printf(FG_BLUE"\t\t\tSeconds Elapsed :"NOCOLOR);
		printf(FG_LTWHITE" %d\n"NOCOLOR, ntohs(bootp->bp_secs));
	}

	if(verbose == 2 || verbose == 3) {
		printf(FG_BLUE"\t\t\tClient IP address :"NOCOLOR);
		printf(FG_LTWHITE" %s\n"NOCOLOR, inet_ntoa(bootp->ciaddr));
		
		printf(FG_BLUE"\t\t\tYour IP Address :"NOCOLOR);
		printf(FG_LTWHITE" %s\n"NOCOLOR, inet_ntoa(bootp->yiaddr));
		
		printf(FG_BLUE"\t\t\tNext Server IP Address :"NOCOLOR);
		printf(FG_LTWHITE" %s\n"NOCOLOR, inet_ntoa(bootp->siaddr));
		
		printf(FG_BLUE"\t\t\tRelay Agent IP Address :"NOCOLOR);
		printf(FG_LTWHITE" %s\n"NOCOLOR, inet_ntoa(bootp->giaddr));
		if(bootp->bp_hlen == 6) {
			printf(FG_BLUE"\t\t\tClient MAC Address :"NOCOLOR);
			printf(FG_LTWHITE" %02x:%02x:%02x:%02x:%02x:%02x\n"NOCOLOR,  
				bootp->bp_chaddr[0],
				bootp->bp_chaddr[1],
				bootp->bp_chaddr[2],
				bootp->bp_chaddr[3],
				bootp->bp_chaddr[4],
				bootp->bp_chaddr[5]);

			if(verbose == 3) {
				printf(FG_BLUE"\t\t\tClient Hardware Address Padding : "NOCOLOR);
				for(i=6; i<16;i++) {
					printf("%02x", bootp->bp_chaddr[i]);
				}
				printf("\n");
			}
		}
		else {
			printf(FG_BLUE"\t\t\tClient Hardware Address Unknown : "NOCOLOR);
			for(i=0; i<16; i++) {
				printf("%02x", bootp->bp_chaddr[i]);
			}
			printf("\n");
		}
	}

	if(verbose == 3) {
		printf(FG_BLUE"\t\t\tServer Host Name : "NOCOLOR);
		if(bootp->bp_sname[0] != 0) {
			for(i=0; i<64 && bootp->bp_sname[i] != 0; i++) {
				if(isprint(bootp->bp_sname[i]))
					printf(FG_LTWHITE"%c"NOCOLOR, bootp->bp_sname[i]);
				else
					printf(".");
			}
			printf("\n");
		}
		else {
			printf(FG_LTWHITE"Not Given\n"NOCOLOR);
		}
		printf(FG_BLUE"\t\t\tBoot File Name : "NOCOLOR);
		if(bootp->bp_file[0] != 0) {
			for(i=0; i<128 && bootp->bp_file[i] != 0; i++) {
				if(isprint(bootp->bp_file[i]))
					printf(FG_LTWHITE"%c"NOCOLOR, bootp->bp_file[i]);
				else
					printf(".");
			}
			printf("\n");
		}
		else {
			printf(FG_LTWHITE"Not Given\n"NOCOLOR);
		}
	}
	
	int j,k;
	u_int32_t tmp;
	if(ntohl(bootp->magic_cookie) == 0x63825363) {
		if(verbose == 3)
		{
			printf(FG_BLUE"\t\t\tMagic Cookie :"NOCOLOR);
			printf(FG_LTWHITE" DHCP (0x%x)\n"NOCOLOR, ntohl(bootp->magic_cookie));
		}
		else if(verbose == 2)
		{
			printf(FG_BLUE"\t\t\tMagic Cookie :"NOCOLOR);
			printf(FG_LTWHITE" DHCP\n"NOCOLOR);
		}

		if(verbose == 2 || verbose == 3)  {
			for(i = sizeof(struct bootphdr); i < data_size && packet[i] != 0xff; i++) {
				printf(FG_BLUE"\t\t\tOption : "NOCOLOR);
				switch((int)packet[i]) {
					case 0:
						printf(FG_LTWHITE"Padding\n "NOCOLOR);
						i++;
						printf(FG_BLUE"\t\t\t\tPadding:"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, (int)packet[i]);
						break;
					case 1:
						printf(FG_LTWHITE"Subnet Mask "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						printf(FG_LTWHITE"%d.%d.%d.%d\n"NOCOLOR, 
							packet[i],
							packet[i+1],
							packet[i+2],
							packet[i+3]);
						i+=k-1;
						break;
						case 50:
						printf(FG_LTWHITE"Requested IP Address "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						printf(FG_LTWHITE"%d.%d.%d.%d\n"NOCOLOR, 
							packet[i],
							packet[i+1],
							packet[i+2],
							packet[i+3]);
						i+=k-1;
						break;
					case 51:
						printf(FG_LTWHITE"IP Adress Lease Time "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						tmp = packet[i] << 24 | packet[i+1] << 16 | packet[i+2] << 8 | packet[i+3];
						printf(FG_LTWHITE"%ds\n"NOCOLOR, tmp);
						i+=k-1;
						break;
					case 52:
						printf(FG_LTWHITE"Option Overload\n "NOCOLOR);
						i++;
						printf(FG_BLUE"\t\t\t\tLength :"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, (int)packet[i]);
						break;
					case 53:
						printf(FG_LTWHITE"DHCP Message Type "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						switch((int)packet[i]) {
							case 1:
								printf(FG_LTWHITE"Discover"NOCOLOR);
								break;
							case 2:
								printf(FG_LTWHITE"Offer"NOCOLOR);
								break;
							case 3:
								printf(FG_LTWHITE"Request"NOCOLOR);
								break;
							case 4:
								printf(FG_LTWHITE"Decline"NOCOLOR);
								break;
							case 5:
								printf(FG_LTWHITE"Ack"NOCOLOR);
								break;
							case 6:
								printf(FG_LTWHITE"Nack"NOCOLOR);
								break;
							case 7:
								printf(FG_LTWHITE"Release"NOCOLOR);
								break;
							default:
								printf(FG_LTWHITE"Unknown"NOCOLOR);
								break;
						}
						i+=k-1;
						printf("\n");
						break;	
					case 54: // length 4
						printf(FG_LTWHITE"DHCP Server Identifier "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						printf(FG_LTWHITE"%d.%d.%d.%d\n"NOCOLOR, 
							packet[i],
							packet[i+1],
							packet[i+2],
							packet[i+3]);
						i+=k-1;				
						break;
					case 55: // length variable
						printf(FG_LTWHITE"Parameter Request List : "NOCOLOR);
						i++;
						for(j=0;j<(int)packet[i];j++) {
							switch(packet[i+j+1]) {
								case 1:
									printf(FG_LTWHITE" Subnet Mask"NOCOLOR);
									break;
								case 3:
									printf(FG_LTWHITE" Router"NOCOLOR);
									break;
								case 6:
									printf(FG_LTWHITE" Domain Name Server"NOCOLOR);
									break;
								case 28:
									printf(FG_LTWHITE" Broadcast Address"NOCOLOR);
									break;
								case 42:
									printf(FG_LTWHITE" Network Time Protocol Servers"NOCOLOR);
									break;
								case 43:
									printf(FG_LTWHITE" Vendor-Specific Information"NOCOLOR);
									break;
									
								default:
									printf(FG_LTWHITE" Unknown"NOCOLOR);
									break;
							}
							if(j != (int)packet[i]-1)
								printf(",");
						}
						i+=((int)packet[i]);
						printf("\n");
						break;
					case 56:
						printf(FG_LTWHITE"Message\n "NOCOLOR);
						i++;
						printf(FG_BLUE"\t\t\t\tLength :"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, (int)packet[i]);
						break;
						
					case 57:
						printf(FG_LTWHITE"Maximum DHCP Message Size\n "NOCOLOR);
						i++;
						printf(FG_BLUE"\t\t\t\tLength :"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, (int)packet[i]);
						printf(FG_BLUE"\t\t\t\tValue : "NOCOLOR);
						for(j=0; j<(int)packet[i];j++)
						{
							printf(FG_LTWHITE"%d"NOCOLOR, (int)packet[i+j+1]);
						 }
						printf("\n");
						i+=j;
						break;
						
					case 58: 
						printf(FG_LTWHITE"Renewal Time Value "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						tmp = packet[i] << 24 | packet[i+1] << 16 | packet[i+2] << 8 | packet[i+3];
						printf(FG_LTWHITE"%ds\n"NOCOLOR, tmp);
						i+=k-1;
						break;
					case 59:
						printf(FG_LTWHITE"Rebinding Time Value "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						tmp = packet[i] << 24 | packet[i+1] << 16 | packet[i+2] << 8 | packet[i+3];
						printf(FG_LTWHITE"%ds\n"NOCOLOR, tmp);
						i+=k-1;
						break;
					case 61:
						printf(FG_LTWHITE"Client Identifier "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						if((int)packet[i] == 1) {
							printf(FG_LTWHITE"%02x.%02x.%02x.%02x.%02x.%02x\n"NOCOLOR, 
								packet[i+1],
								packet[i+2],
								packet[i+3],
								packet[i+4],
								packet[i+5],
								packet[i+6]);
						}
						else {
							printf(FG_LTWHITE"Unknown Identifier\n"NOCOLOR);
						}
						i += k-1;
						break;
					case 255:
						printf(FG_LTWHITE"End (Option End: 255) "NOCOLOR);
						break;
					default:
						printf(FG_LTWHITE"Unknown (%d)\n"NOCOLOR, (int)packet[i]);
						i++;
						printf(FG_BLUE"\t\t\t\tLength :"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, (int)packet[i]);
						printf(FG_BLUE"\t\t\t\tValue : "NOCOLOR);
						for(j=0; j<(int)packet[i];j++) {
							printf(FG_LTWHITE"0x%d"NOCOLOR, (int)packet[i+j+1]);
						}
						printf("\n");
						i+=j;
						break;
				}
			}
		}
		else {
			for(i = sizeof(struct bootphdr); i < data_size && packet[i] != 0xff; i++) {
				switch((int)packet[i]) {
				
				  case 255:
						printf(FG_LTWHITE"End (Option End: 255) "NOCOLOR);
						break;
					case 56:
						printf(FG_LTWHITE"Message\n "NOCOLOR);
						i++;
						printf(FG_BLUE"\t\t\t\tLength :"NOCOLOR);
						printf(FG_LTWHITE" %d\n"NOCOLOR, (int)packet[i]);
						break;
					case 53:
						printf(FG_BLUE"\t\t\t\t\t\t\t\t\t |_DHCP: "NOCOLOR);
						i++;
						k = (int)packet[i];
						i++;
						switch((int)packet[i]) {
							case 1:
								printf(FG_LTWHITE"Discover"NOCOLOR);
								break;
							case 2:
								printf(FG_LTWHITE"Offer"NOCOLOR);
								break;
							case 3:
								printf(FG_LTWHITE"Request"NOCOLOR);
								break;
							case 4:
								printf(FG_LTWHITE"Decline"NOCOLOR);
								break;
							case 5:
								printf(FG_LTWHITE"Ack"NOCOLOR);
								break;
							case 6:
								printf(FG_LTWHITE"Nack"NOCOLOR);
								break;
							case 7:
								printf(FG_LTWHITE"Release"NOCOLOR);
								break;
							default:
								printf(FG_LTWHITE"Unknown"NOCOLOR);
								break;
						}
						i+=k-1;
						break;
					default:
						i++;
						k = (int)packet[i];
						i+=k-1;
						break;
				}
			}
		}
	}
	else {
		printf(FG_BLUE"\t\t\tVendor Specific :"NOCOLOR);
		printf(FG_LTWHITE" Not Given\n"NOCOLOR);
	}
}


// gestion des paquets dns
void dns(const unsigned char *packet, int data_size, int verbose) {
	struct _dnshdr *dns = (struct _dnshdr*)(packet);
	int i, j = 0, k, questions, answers;
	u_int16_t *type, *class, *d_size;
	u_int32_t *ttl;

	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t\t\t#### DNS ####\n"NOCOLOR);
	}

	if(verbose == 3) {
		printf(FG_CYAN"\t\t\tQuery id : "NOCOLOR);
		printf(FG_LTWHITE"0x%04x\n"NOCOLOR, ntohs(dns->query_id));
		printf(FG_CYAN"\t\t\tFlags : "NOCOLOR);
		printf(FG_LTWHITE"0x%04x\n"NOCOLOR, ntohs(dns->flags));
	}

	if(verbose == 2 || verbose == 3) {
		printf(FG_CYAN"\t\t\tQuestions : "NOCOLOR);
		printf(FG_LTWHITE"%d\n"NOCOLOR, ntohs(dns->quest_count));
		printf(FG_CYAN"\t\t\tAnswer RRS : "NOCOLOR);
		printf(FG_LTWHITE"%d\n"NOCOLOR, ntohs(dns->answ_count));
		printf(FG_CYAN"\t\t\tAuthority RRs : "NOCOLOR);
		printf(FG_LTWHITE"%d\n"NOCOLOR, ntohs(dns->auth_count));
		printf(FG_CYAN"\t\t\tAdditional RRs : "NOCOLOR);
		printf(FG_LTWHITE"%d\n"NOCOLOR, ntohs(dns->add_count));
	}

	questions = ntohs(dns->quest_count);
	answers = ntohs(dns->answ_count);

	if(verbose == 2 || verbose == 3) {
		if(questions > 0) {
			printf(FG_CYAN"\t\t\tQueries:\n"NOCOLOR);
			for(k = 0; k < questions; k++) {
				printf("\t\t\t   ");
				for(i = sizeof(struct _dnshdr) + j; i < data_size && packet[i] != 0x00; i++) {
/*					if(packet[i] == 0x03)*/
/*						printf(FG_LTWHITE"."NOCOLOR);*/
					/*else*/ if(packet[i] != 0x0c) {
						if(isprint(packet[i]))
							printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);
/*						else*/
/*							printf(FG_LTWHITE"."NOCOLOR);*/
					}
				}
				j = i+1;
				printf("\n");

				if(verbose == 2 || verbose == 3) {
					type = (u_int16_t*)(packet + j);
					j+=2;
					class = (u_int16_t*)(packet + j);

					if(verbose == 3) {
						printf(FG_LTWHITE"\t\t\t   0x%04x : "NOCOLOR, ntohs(*type));
						switch(ntohs(*type)) {
							case 1:
								printf(FG_LTWHITE" Type A (Address Record)\n"NOCOLOR);
								break;
							case 28:
								printf(FG_LTWHITE"Type AAAA (IPv6 Address Record)\n"NOCOLOR);
								break;
							case 5:
								printf(FG_LTWHITE" Type CNAME (Canonical Name Record)\n"NOCOLOR);
								break;
							case 15:
								printf(FG_LTWHITE" Type MX (Mail Exchange Record)\n"NOCOLOR);
								break;
							case 2:
								printf(FG_LTWHITE"Type NS (Name Server Record)\n"NOCOLOR);
								break;
							case 6:
								printf(FG_LTWHITE"Type SOA (Start of Authority Record)\n"NOCOLOR);
								break;
							case 16:
								printf(FG_LTWHITE"Type TXT (Text Record)\n"NOCOLOR);
								break;
							default:
								printf(FG_LTWHITE" Type Unknown\n"NOCOLOR);
								break;
						}

						printf(FG_LTWHITE"\t\t\t   0x%04x : "NOCOLOR, ntohs(*class));
						switch(ntohs(*class)) {
							case 0:
								printf(FG_LTWHITE"Class Reserved\n"NOCOLOR);
								break;
							case 1:
								printf(FG_LTWHITE"Class Internet\n"NOCOLOR);
								break;
							case 2:
								printf(FG_LTWHITE"Class Unassigned\n"NOCOLOR);
								break;
							case 3:
								printf(FG_LTWHITE"Class Chaos\n"NOCOLOR);
								break;
							case 4:
								printf(FG_LTWHITE"Class Hesiod\n"NOCOLOR);
								break;
							default:	
								printf(FG_LTWHITE"Class Unknown\n"NOCOLOR);
								break;
						}
					}
				}
				else {
					j+=2;
				}
			}
		}

		if(answers > 0) {
			printf(FG_CYAN"\t\t\tAnswers\n"NOCOLOR);
			for(k = 0; k < answers; k++) {
				j += 4;
				type = (u_int16_t*)(packet + j);
				j += 2;
				class = (u_int16_t*)(packet + j);
				j += 2;
				ttl = (u_int32_t*)(packet + j);
				j += 4;
				d_size = (u_int16_t*)(packet + j);
				j += 2;

				if(verbose == 3) {
					printf(FG_LTWHITE"\t\t\t   Type 0x%04x\n"NOCOLOR, ntohs(*type));
					printf(FG_LTWHITE"\t\t\t   Data Length %d\n"NOCOLOR, ntohs(*d_size));
					printf(FG_LTWHITE"\t\t\t   Time To Live %d\n"NOCOLOR, ntohs(*ttl));
				}
				if(ntohs(*type) == 1) {
					printf(FG_LTWHITE"\t\t\t   %d.%d.%d.%d\n"NOCOLOR, 
						packet[j], 
						packet[j+1],
						packet[j+2],
						packet[j+3]);
				}
				else {
					for(i = 0; i < ntohs(*d_size); ++i)
					{
						printf(FG_LTWHITE"%c"NOCOLOR, packet[j+i]);
					}

					printf("\n");

					j += ntohs(*d_size);
				}

			}

			printf("\n");
		}
	}

	if(verbose == 1) {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t         |_[DNS] "NOCOLOR);
		if(answers > 0)
			printf(FG_LTWHITE"Answer\n"NOCOLOR);
		else if(questions > 0)
			printf(FG_LTWHITE"Query\n"NOCOLOR);
	}
}


// gestion des paquets http
void http(const unsigned char *packet, int data_size, int verbose) {
	int i;


	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t\t\t#### HTTP ####\n"NOCOLOR);

		printf("\t\t\t");

		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);
			else 
				printf(".");
		}
	}
	else {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t\t\t   |_[HTTP] ");
		if(!islower(packet[0])) {
			for (i = 0; i < data_size; ++i) 
			{
				if(isprint(packet[i]))
					printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);
				else 
					printf(FG_LTWHITE"."NOCOLOR);

				if(packet[i] == ' ')
					break;
			}	
		}
		else
			printf(FG_LTWHITE"data"NOCOLOR);	
	}
}

// gestion des paquets ftp
void ftp(const unsigned char *packet, int data_size, int verbose) {
	int i;

	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t\t\t#### FTP ####\n"NOCOLOR);
		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);	
			else
				printf(".");
		}

		printf("\n");	
	}
	else {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t\t\t   |_[FTP] ");
		for (i = 0; i < data_size && packet[i] != '\n'; ++i) 
		{
			if(isprint(packet[i]))
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);
		}
	}

}

// gestion des paquets smtp
void smtp(const unsigned char *packet, int data_size, int verbose) {
	int i;

	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t\t\t#### SMTP ####\n"NOCOLOR);
		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);	
			else
				printf(FG_LTWHITE"."NOCOLOR);
		}

		printf("\n");	
	}
	else {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t\t\t   |_[SMTP] ");
		for (i = 0; i < data_size && packet[i] != ' '; ++i) 
		{
			if(isprint(packet[i]))
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);	
			else
				printf(FG_LTWHITE"."NOCOLOR);
		}
	}

}

// gestion des paquets pop
void pop(const unsigned char *packet, int data_size, int verbose) {
	int i;

	if(verbose == 2 || verbose == 3) 
	{
		printf(FG_LTYELLOW"\t\t\t#### POP ####\n"NOCOLOR);

		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);
			else
				printf(FG_LTWHITE"."NOCOLOR);	
		}

		printf("\n");	
	}
	else {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t\t\t   |_[POP] " );
		for (i = 0; i < data_size && packet[i] != ' '; ++i) 
		{
			if(isprint(packet[i]))
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);	
			else
				printf(FG_LTWHITE"."NOCOLOR);
		}
	}
}

// gestion des paquets imap
void imap(const unsigned char *packet, int data_size, int verbose) {
	int i;

	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t\t\t#### IMAP ####\n"NOCOLOR);

		printf("\t\t\t");
		for (i = 0; i < data_size; ++i) 
		{
			if(packet[i-1] == '\n')
				printf("\t\t\t");

			if(isprint(packet[i]) || packet[i] == '\n' || packet[i] == '\t' || packet[i] == '\r')
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);	
			else
				printf(".");
		}

		printf("\n");
	}
	else {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t\t\t   |_[IMAP]"NOCOLOR);
		for (i = 0; i < data_size && packet[i] != '\n'; ++i) 
		{
			if(isprint(packet[i]))
				printf(FG_LTWHITE"%c"NOCOLOR, packet[i]);	
			else
				printf(".");
		}		
	}	
}

// gestion des paquets telnet
void telnet(const unsigned char *packet, int data_size, int verbose) {
	int i = 0, j = 1;

	if(verbose == 2 || verbose == 3) {
		printf(FG_LTYELLOW"\t\t\t#### TELNET ####\n"NOCOLOR);

		while(i < data_size) 
		{
			if(packet[i] == 255) {
				i++;
				j = 1;
				printf("\t\t\t");
				while(j) {
					switch(packet[i]) {
						case 0:
							printf(FG_LTWHITE"Binary transmission ");
							break;
						case 1:
							printf(FG_LTWHITE"Echo ");
							break;
						case 2:
							printf(FG_LTWHITE"Reconnection ");
							break;
						case 3:
							printf(FG_LTWHITE"Suppress go ahead ");
							break;
						case 4:
							printf(FG_LTWHITE"Approx message size negotation ");
							break;
						case 5:
							printf(FG_LTWHITE"Status ");
							break;
						case 6:
							printf(FG_LTWHITE"Timing mark ");
							break;
						case 7:
							printf(FG_LTWHITE"Remote controlled transmition and echo");
							break;
						case 8:
							printf(FG_LTWHITE"Output line width ");
							break;
						case 9:
							printf(FG_LTWHITE"Output page size ");
							break;
						case 10:
							printf(FG_LTWHITE"Output carriage-return disposition ");
							break;
						case 11:
							printf(FG_LTWHITE"Output horizontal tabstops ");
							break;
						case 12:
							printf(FG_LTWHITE"Output horizontal tab disposition ");
							break;
						case 13:
							printf(FG_LTWHITE"Output formfeed disposition ");
							break;
						case 14:
							printf(FG_LTWHITE"Output vertical tabstops ");
							break;
						case 15:
							printf(FG_LTWHITE"Output vertical tab disposition ");
							break;
						case 16:
							printf(FG_LTWHITE"Output linefeed disposition ");
							break;
						case 17:
							printf(FG_LTWHITE"Extended ASCII ");
							break;
						case 18:
							printf(FG_LTWHITE"Logout ");
							break;
						case 19:
							printf(FG_LTWHITE"Byte macro ");
							break;
						case 20:
							printf(FG_LTWHITE"Data entry terminal ");
							break;
						case 21:
							printf(FG_LTWHITE"SUPDUP ");
							break;
						case 22:
							printf(FG_LTWHITE"SUPDUP output ");
							break;
						case 23:
							printf(FG_LTWHITE"Send location ");
							break;
						case 24:
							printf(FG_LTWHITE"Terminal type ");
							break;
						case 25:
							printf(FG_LTWHITE"End of record ");
							break;
						case 26:
							printf(FG_LTWHITE"TACACS user identification ");
							break;
						case 27:
							printf(FG_LTWHITE"Output marking");
							break;
						case 28:
							printf(FG_LTWHITE"Terminal location number ");
							break;
						case 29:
							printf(FG_LTWHITE"Telnet 3270 regime ");
							break;
						case 30:
							printf(FG_LTWHITE"X.3 PAD ");
							break;
						case 31:
							printf(FG_LTWHITE"Window size ");
							break;
						case 32:
							printf(FG_LTWHITE"Terminal speed ");
							break;
						case 33:
							printf(FG_LTWHITE"Remote flow control ");
							break;
						case 34:
							printf(FG_LTWHITE"Linemode ");
							break;
						case 35:
							printf(FG_LTWHITE"X display location");
							break;
						case 36:
							printf(FG_LTWHITE"Environment variables ");
							break;
						case 39:
							printf(FG_LTWHITE"New environment options ");
							break;
						case 240:
							printf(FG_LTWHITE"End of subnegotiation parameters ");
							break;
						case 241:
							printf(FG_LTWHITE"No operation ");
							break;
						case 242:
							printf(FG_LTWHITE"Data mark ");
							break;
						case 243:
							printf(FG_LTWHITE"Break ");
							break;
						case 244:
							printf(FG_LTWHITE"Suspend ");
							break;
						case 245:
							printf(FG_LTWHITE"Abort output ");
							break;
						case 246:
							printf(FG_LTWHITE"Are you there ");
							break;
						case 247:
							printf(FG_LTWHITE"Erase character ");
							break;
						case 248:
							printf(FG_LTWHITE"Erase line ");
							break;
						case 249:
							printf(FG_LTWHITE"Go ahead ");
							break;
						case 250:
							printf(FG_LTWHITE"Subnegotiation ");
							break;
						case 251:
							printf(FG_LTWHITE"WILL ");
							break;
						case 252:
							printf(FG_LTWHITE"WON'T ");
							break;
						case 253:
							printf(FG_LTWHITE"DO ");
							break;
						case 254:
							printf(FG_LTWHITE"DON'T ");
							break;
						default:
							printf(FG_LTWHITE"%c ", packet[i]);
							break;
					}

					i++;
					if(packet[i] == 255 || i >= data_size) {
						j = 0;
						printf("\n");
					}
				}
			}
			else {
				if(packet[i-1] == '\n' || packet[i-1] == '\r' || i == 0) {
					printf("\t\t\t");
				}
				printf(FG_LTWHITE"%c", packet[i]);
				i++;
			}
		}

		printf("\n");	
	}
	else {
		printf(FG_BLUE"\t\t\t\t\t\t\t\t\t\t   |_[TELNET]"NOCOLOR);
	}
}
