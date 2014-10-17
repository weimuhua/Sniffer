#all:sniffer.c
#	gcc -g -Wall -o sniffer sniffer.c -lpcap
sniffer:sniffer.o proto.o
	gcc -o  sniffer sniffer.o proto.o -g -Wall -lpcap
clean:
	rm -rf proto.o sniffer.o
