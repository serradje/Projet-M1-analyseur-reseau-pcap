CFLAGS= -Wall -g -Wextra
LDLIBS= -lpcap
CC=gcc

vpath %.o obj/
vpath %.c src/
vpath %.h include/
vpath analyseur /bin


all : analyseur

analyseur : main.o application.o transport.o reseau.o liaison.o
	$(CC) $(CFLAGS) -g -o $@ obj/main.o obj/application.o obj/transport.o obj/reseau.o obj/liaison.o $(LDLIBS)
	mv $@ bin/.

main.o : bootp.h color.h
application.o : bootp.h color.h
transport.o : bootp.h color.h
reseau.o : bootp.h color.h
liaison.o : bootp.h color.h

%.o : %.c
	$(CC) $(CFLAGS) -c $< -Iinclude $(LDLIBS)
	mv $@ obj/
clean :
	rm -rf obj/*.o bin/* analyseur include/*.gch
		
archive :
	tar -f Analyseur_Reseau_Serradj_Elhadi.tar.gz -cvz src/*.c include/*.h Makefile rapport.pdf bin/ obj/
