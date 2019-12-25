# analyseur réseau
Projet M1 SIRIS services réseau

#Protocoles supportés: 

- Ethernet
- IPv4
- UDP, TCP, ARP
- BOOTP, DHCP, DNS, HTTP, FTP, SMTP, POP, IMAP, TELNET


lancement : sudo ./analyse -i interface -v 3 ...

#Usage:

-i <interface> : `interface pour l’analyse live`
-o <fichier> : `fichier d’entrée pour l’analyse offline`
-f <filtre> : `filtre BPF (optionnel)`
-v <1..3> : `niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)`
-d < affiche toutes les interfaces>

