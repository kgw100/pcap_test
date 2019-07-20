#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define eth_ 6
#define ip_start 26
#define ip_count 4
#define ip_number 0x0800
#define tcp_number 6
#define tcpPort_start 34
#define tcpData_start 54
#define tcpData_count 10

void ether_print(const u_char *mac);
void ip_print(const u_char *ip);
void tcp_print(const u_char *tcp);
void tcpData_print(int Total_length, int IHL, int THL, const u_char *TcpData);

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
   int i = 1;
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

    if (res == 0) continue;
    if (res == -1 || res == -2)
      break;
     uint16_t ip_check = (packet[12]<<8)|packet[13];
     int tcp_check = packet[23];
     int TotalSize= ((packet[16]<<8) | packet[17]);
     int IHL =((packet[14]& 0x0F)<< 2);
     int THL =((packet[46]&0xF0) >> 2);

    if( ip_number == ip_check &&  tcp_number == tcp_check){
   printf("--------------Packet[%d]---------------\n\n",i);
   printf("eth.Dmac::");
   ether_print(packet);
   printf("eth.Smac::");
   ether_print(packet+6);
   printf("Ether_Type::");
   printf("%02X%02X\n",packet[12],packet[13]);
   printf("ip.sip::");
   ip_print(&packet[ip_start]);
   printf("ip.dip::");
   ip_print(&packet[ip_start+4]);
   printf("Protocal::");
   printf("%d\n",packet[23]);
   printf("tcp.sport::");
   tcp_print(&packet[tcpPort_start]);
   printf("tcp.dport::");
   tcp_print(&packet[tcpPort_start+2]);
   printf("tcp.data::");
   tcpData_print(TotalSize,IHL,THL,&packet[tcpData_start]);
      i++;
    }

   //tcpdata_size==total length - lhp - tcp dataoffset
  //printf("%u bytes captured\n", header->caplen);

  }

  pcap_close(handle);
  return 0;
}

void ether_print(const u_char* mac)
{
    int i = 0;
    for(  ; i<5; i++){
     printf("%02X:",mac[i]);
    }
    printf("%02X\n",mac[i]);
    }
void ip_print(const u_char* ip)
{
    int i = 0;
    for(  ; i<3; i++){
     printf("%u.",ip[i]);
    }
    printf("%u\n",ip[i]);
}
void tcp_print(const u_char *tcp)
{
    printf("%02u\n", (tcp[0]<<8) | tcp[1]);
}
void tcpData_print(int Total_length, int IHL, int THL, const u_char *TcpData)
{
    int i = 0;
    int TcpData_size = Total_length - IHL -THL;
    if(TcpData_size == 0)
    {
        printf("No Data!!\n");
    }
    else if ( 0 <TcpData_size && TcpData_size<=10)
    {

        for(  ; i<TcpData_size-1; i++){
         printf("%02X ",TcpData[i]);
        }
        printf("%02X\n",TcpData[i]);
    }
    else
    {
        for(  ; i<9; i++){
         printf("%02X ",TcpData[i]);
        }
        printf("%02X\n",TcpData[i]);

    }


}
