#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <netinet/in.h>
//#include <linux/if_ether.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_MAC(const u_char* MAC){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}

void print_ip(ulong IP){
    uint32_t Ip= ntohl((uint32_t)IP);
    printf("%u.%u.%u.%u\n", (Ip & 0xff000000) >> 24, (Ip & 0x00ff0000) >> 16, (Ip & 0x0000ff00) >> 8, (Ip & 0x000000ff));
}

void print_TCP(u_short TCP){
    printf("%d\n", ntohs(TCP));
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
   return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    struct libnet_ethernet_hdr *Ether;
    //struct ethhdr *Ether;
    struct libnet_tcp_hdr *TCP;
    struct libnet_ipv4_hdr *IP;
    //struct ip *IP;
    //struct tcphdr *TCP;

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    Ether = (struct libnet_ethernet_hdr *)packet;
    packet += 14;
    IP = (struct libnet_ipv4_hdr *)packet;
    int hl = IP->ip_hl*4;
    packet += hl;
    TCP = (struct libnet_tcp_hdr *)packet;

    printf("--------------------------------------------------\n");
    printf("DMAC: ");
    print_MAC(Ether->ether_dhost);
    printf("SMAC: ");
    print_MAC(Ether->ether_shost);
    if(Ether->ether_type == 0x0008){
        printf("Dip: ");
        print_ip(IP->ip_dst.s_addr);
        printf("Sip: ");
        print_ip(IP->ip_src.s_addr);
        if(IP->ip_p == 0x6){
            printf("DPort: ");
            print_TCP(TCP->th_dport);
            printf("SPort: ");
            print_TCP(TCP->th_sport);
            if(ntohs(IP->ip_len)-hl-TCP->th_off*4 != 0){
                int len = ntohs(IP->ip_len)-hl-TCP->th_off*4;
                packet += TCP->th_off*4;
                printf("TCP data: ");
                for(int i = 0; i < 10 && i < len; i++) printf("%02x ", packet[i]);
                printf("\n");
            }
        }
    }
    printf("--------------------------------------------------\n\n\n");
  }

  pcap_close(handle);
  return 0;
}
