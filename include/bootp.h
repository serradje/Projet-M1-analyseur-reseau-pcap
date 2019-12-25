#ifndef APPLICATION_H
#define APPLICATION_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#ifdef SUPPORT_DHCP
#define BOOTP_VENDSIZE 312
#else
#define BOOTP_VENDSIZE 64
#endif

#define IP_ALEN 4

struct _arpaddr
{
	unsigned char ar_sha[ETH_ALEN];
	unsigned char ar_spa[IP_ALEN];
	unsigned char ar_tha[ETH_ALEN];
	unsigned char ar_tpa[IP_ALEN];
};

struct _dnshdr {
	u_int16_t query_id;
	u_int16_t flags;
	u_int16_t quest_count;
	u_int16_t answ_count;
	u_int16_t auth_count;
	u_int16_t add_count;
};

typedef struct {
	u_int8_t type;
	u_int8_t length;
	u_int8_t value[32];
} tlv;

struct bootphdr {
	u_int8_t bp_op;				/* packet opcode type */
	u_int8_t bp_htype;			/* hardware addr type */
	u_int8_t bp_hlen;			/* hardware addr length */
	u_int8_t bp_hops;			/* gateway hops */
	u_int32_t bp_xid;			/* transaction ID */
	u_int16_t bp_secs;			/* seconds since boot began */
	u_int16_t bp_flags;			/* flags: 0x8000 is broadcast */
	struct in_addr ciaddr;		/* client IP address */
	struct in_addr yiaddr;		/* 'your' IP address */
	struct in_addr siaddr;		/* server IP address */
	struct in_addr giaddr;		/* gateway IP address */
	u_char bp_chaddr[16];		/* client hardware address */
	u_char bp_sname[64];		/* server host name */
	u_char bp_file[128];		/* boot file name */
	u_int32_t magic_cookie; 	/* gateway IP address */
};


/** protocole ETHERNET
 * get and display data
 */
void ethernet(const unsigned char *, int);

/** protocole IP
 * get and display data
 */

void ip(const unsigned char*, int);

/** protocole ARP
 * get and display data
 */
 
void arp(const unsigned char*, int);

/** protocole UDP
 * get and display data
 */
 
void udp(const unsigned char*, int);

/** protocole TCP
 * get and display data
 */
 
void tcp(const unsigned char*, unsigned char, int);

/** application BOOTP
 * get and display data
 */
 
void bootp(const unsigned char*, int, int);

/** application DNS
 * get and display data
 */
void dns(const unsigned char*, int, int);

/** application HTTP
 * get and display data
 */
void http(const unsigned char*, int, int);

/** application FTP
 * get and display data
 */
void ftp(const unsigned char*, int, int);

/** application SMTP
 * get and display data
 */
void smtp(const unsigned char*, int, int);

/** application POP
 * get and display data
 */
void pop(const unsigned char*, int, int);

/** application IMAP
 * get and display data
 */
void imap(const unsigned char*, int, int);

/** application TELENET
 * get and display data
 */
void telnet(const unsigned char*, int, int);

#endif
