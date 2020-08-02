#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "headers.h"
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

u_char *sub_str(const u_char *input, int i_begin, int i_end);
int ethernet(const u_char *temp);
int ipv4(const u_char *temp);
int tcp_pcap(const u_char *temp);
int payload_len(const u_char *ip);
void usage();

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    int next = 0;
    char* dev = argv[1]; // dev = enp0s3
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        /* res = -1 is error ouccrrence
           res = -2 is EOF */

        printf("%u bytes captured\n", header->caplen);

        if(ethernet(packet) == 1)
        {
            packet = packet +14;
            int tcp_paylen = payload_len(packet);
            
            next = ipv4(packet);
            if (next != 0){
                printf("%d\n",next);
                packet=packet+next;
                
                int headerlen = tcp_pcap(packet);
                printf("packet length : %d byte \n",tcp_paylen );
                printf("packet content\t");
                int min = (tcp_payload>16)? 16: tcp_paylen;
                for(int i = 0; i<min; i++) {
                    printf("%02x",(packet+headerlen)[i]);
                    if(i<min -1) printf(":");
                    else printf("\n");
                }
            }
        }
        else
            return 0;


        printf("\n\n\n------------------------------\n\n\n");
    }

    pcap_close(handle);
    return 0;
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}



int ethernet(const u_char *temp)
{
    struct libnet_ethernet_hdr* etherpacket;
    etherpacket = (struct libnet_ethernet_hdr*)temp;
    if(ntohs(etherpacket->ether_type) == ETHERTYPE_IP )
    {
        for(int i = 0; i<ETHER_ADDR_LEN; i++) {
            printf("%02x",etherpacket->ether_dhost[i]);
            if(i<ETHER_ADDR_LEN -1) printf(":");
            else printf("\n");
        }

        for(int i = 0; i<ETHER_ADDR_LEN; i++){
            printf("%02x",etherpacket->ether_shost[i]);
            if(i<ETHER_ADDR_LEN -1) printf(":");
            else printf("\n");
        }

        return 1;
    }
    else
        return 0;
}


int ipv4(const u_char *temp)
{
    struct libnet_ipv4_hdr *ip_packet = (struct libnet_ipv4_hdr*)temp;
    //ip_packet->ip_src = inet_ntoa(ip_packet->ip_src);
    printf("ip_source is %s\n", inet_ntoa(ip_packet->ip_src));
    printf("ip_destination is %s\n", inet_ntoa(ip_packet->ip_dst));

    if(ip_packet->ip_p == 0x06){
        printf("lenght: %x\n",ip_packet->ip_hl );
        return ip_packet->ip_hl<<2;
    }
    else
        return 0;
}
int payload_len(const u_char *ip)
{
    struct libnet_ipv4_hdr *ip_packet = (struct libnet_ipv4_hdr*)ip;
    return (ip_packet ->ip_len - (ip_packet -> ip_hl << 2));
}

int tcp_pcap(const u_char *temp)
{

    struct libnet_tcp_hdr *tcp_packet =(struct libnet_tcp_hdr *) temp;

    printf("tcp_source_port is %d\n", ntohs(tcp_packet->th_sport));
    printf("tcp_destination_port is %d\n", ntohs(tcp_packet->th_dport));
    return tcp_packet->th_off<<2;

}
