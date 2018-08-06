all : send_arp

pcap_test: main.o
        g++ -g -o pcap_test main.o -lpcap

main.o:
        g++ -g -c -o main.o main.cpp

clean:
        rm -f send_arp
        rm -f *.o
