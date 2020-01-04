/**
 * file main.c
 * contient la fonction principale du programme
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "bootp.h"
#include "color.h"

int n;
pcap_t *p = NULL;
pcap_if_t *alldevs,*cpt;

/** usage(): Affiche la syntaxe du programme
 * 
 * fonctions pour regrouper les messages à un seul endroit.
 * @param prog nom du programme
 * 
 */
 
void usage (const char *prog)
{
    fprintf (stderr,FG_LTYELLOW"usage: %s ./analyse -i <interface> -o <fichier> -f <filter> -v <1..3>\n" 
    			"\t-d   : afficher toutes les interfaces\n"
    			"\t-i   : <interface> : interface pour l’analyse live\n"
    			"\t-o   : <fichier> : fichier d’entrée pour l’analyse offline\n"
    			"\t-f   : <filtre> : filtre BPF (optionnel)\n"
    			"\t-v   : <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)\n"
    			"\t-h   : afficher de l'aide\n"NOCOLOR
    		, prog);/* on affichera ceci l'orsque qu'une erreur dans les arguments surviennent */
    exit(0);		 
}

/* Gestion des Paquets */
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
	struct tm *ts;
	char buf[80];
	n++;
	ts = localtime(&(header->ts.tv_sec));
	strftime(buf, sizeof(buf), FG_LTYELLOW"%a %Y-%m-%d %H:%M:%S %Z"NOCOLOR, ts);
	if(*args == 1)
		fprintf(stderr,FG_LTYELLOW"[%d]: "NOCOLOR, n);
	else
		
	fprintf(stderr,FG_LTYELLOW"Packet [%d] : Length %d Bytes, %s\n"NOCOLOR, n,header->len, buf );
	ethernet(packet, *args);
	printf("\n");
				
}
 /* Fonction permetant d'afficher toutes les interfaces */
void display_All_devices()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	if( (pcap_findalldevs(&alldevs, errbuf)) == -1)
	{
	
		fprintf(stderr," erron in findall devs\n");
		exit(1);
	}
	printf(FG_LTYELLOW"Interfaces de votre machine:\n"NOCOLOR);
	for(cpt=alldevs;cpt;cpt=cpt->next)
	{
		fprintf(stderr, FG_LTWHITE"%d : %s\n"NOCOLOR, i++,cpt->name);
	}
	exit(0);
}

/* Fonction traitant la reception du signal SIGINT */
static void handler() {
    pcap_breakloop(p);
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	n = 0;
	int v, verbose;
	char c;
	char *file = NULL, *filter = NULL, *dev = NULL;

    //reception du signal SIGINT.
	signal(SIGINT, handler);
      
    // gestion des options
	while((c = getopt(argc, argv, "di:o:f:v:h")) != -1) {
		switch(c) {
			case 'i':
				dev = optarg;
				break;
			case 'o':
				file = optarg;
				break;
			case 'f':
				filter = optarg;
				break;
			case 'v':
				v = atoi(optarg);
				if(v != 1 && v != 2 && v != 3)
				{
					fprintf(stderr,FG_LTWHITE"\nniveau de verbosité doit être compris entre <1..3>\n"NOCOLOR);
					verbose = 3;
					fprintf(stderr,FG_LTYELLOW"-v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)\n"
									"\tLa Verbositée par Default [3=complet] va être appliquer...\n\n"NOCOLOR);
					sleep(3);
				}
				else 
				verbose = v;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'd':
				display_All_devices();
				break;
			case '?':
				usage(argv[0]);
				break;
		}
	}
	
	//pas d'interface? l'interface par defaut est selctionnée
	if(dev == NULL) 
	{
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) 
			{
				fprintf(stderr, "Couldn't Find Default Device: %s\n", errbuf);
				return -1;
			}
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
	{
		fprintf(stderr, "Couldn't Get Netmask For Device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	if(file == NULL) 
	{
		p = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
			if (p == NULL) 
				{
					fprintf(stderr, "Couldn't Open Device %s: %s\n", dev, errbuf);
					return -1;
				}
	
		if(filter != NULL) 
		{
			if (pcap_compile(p, &fp, filter, 0, net) == -1) 
				{
					fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(p));
					return -1;
				}
			if (pcap_setfilter(p, &fp) == -1) 
				{
					fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(p));
					return -1;
				}
		}
	}
	else 
	{
		p = pcap_open_offline(file, errbuf);
		if (p == NULL) 
			{
				fprintf(stderr, "Couldn't open the file %s: %s\n", file, errbuf);
				return -1;
			}
	}
	printf(FG_LTYELLOW"Interface sélectionnée par Défault: %s\n\n"NOCOLOR, dev);

	pcap_loop(p, -1, packet_handler, (u_char*)&verbose);
	printf(FG_LTYELLOW"\n\n%d packet captured\n"NOCOLOR, n);

	pcap_close(p);
	return 0;
}
