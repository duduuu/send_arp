all: send_arp

send_arp: main.o
	g++ -o send_arp main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f *.o
	rm -f send_arp
