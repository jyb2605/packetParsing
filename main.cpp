#include <pcap.h>
#include <stdio.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {

  u_char smac[6], dmac[6];
  u_char sip[4], dip[4];
  u_char sport[2], dport[2]; 

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
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    
    //for(int i=0; i<header->caplen; i++){
    //	printf("%u ", packet[i]);
    //}
    
    memcpy(dmac, &packet[0], 6);
    memcpy(smac, &packet[6], 6);
    memcpy(sip, &packet[28], 4);
    memcpy(dip, &packet[38], 4);
    memcpy(sip, &packet[42], 2);
    memcpy(dip, &packet[44], 2);

    
    printf("source mac address : ");
    for(int i=0; i<6; i++){
    	printf("%x ", smac[i]);
    }
    printf("\n");

    printf("destination mac address : ");
    for(int i=0; i<6; i++){
	    printf("%x ", dmac[i]);
    }
    printf("\n");

    printf("source ip address : ");
    for(int i=0; i<4; i++){
            printf("%x ", sip[i]);
    }
    printf("\n");

    printf("destination ip address : ");
    for(int i=0; i<4; i++){
            printf("%x ", dip[i]);
    }
    printf("\n");

    printf("source port number : ");
    for(int i=0; i<2; i++){
            printf("%x ", sport[i]);
    }
    printf("\n");

    printf("destination port number : ");
    for(int i=0; i<2; i++){
            printf("%x ", dport[i]);
    }
    printf("\n");



  }

  pcap_close(handle);
  return 0;
}
