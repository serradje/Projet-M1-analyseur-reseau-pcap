# analyseur réseau
Projet M1 SIRIS services réseau

#Protocoles supportés: 

- Ethernet
- IPv4/IPv6
- UDP, TCP, ARP
- BOOTP, DHCP, DNS, HTTP, FTP, SMTP, POP, IMAP, TELNET


#lancement :
						sudo ./analyse -d "pour voir toutes les interfaces et chosir celle qu'on veut analyser
															 sinon,une interface par defaut est choisi"
						sudo ./analyse -v [1,2,3]
						sudo ./analyse -v [1,2,3]	-o file	...

#Usage:

-i <interface> : `interface pour l’analyse live`
-o <fichier> : `fichier d’entrée pour l’analyse offline`
-f <filtre> : `filtre BPF (optionnel)`
-v <1..3> : `niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)`
-d < affiche toutes les interfaces>

