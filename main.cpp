#include <pcap.h>
#include <stdio.h>
#include <string.h>

#define ETHER_HEADER_LENGTH 14
#define IPV4_NUM 4
#define IPV6_NUM 6
#define TCP_HEADER_LENGTH 20

typedef struct _ethernet{
	u_char source_mac[6];
	u_char destination_mac[6];
	u_char type[2];

	void print(){
	    printf("source mac address : ");
	    for(int i=0; i<6; i++){
	        printf("%x", source_mac[i]);
	        if( i!= 5)
                	printf(":");
	    }
	    printf("\n");

	    printf("destination mac address : ");
	    for(int i=0; i<6; i++){
	        printf("%x", destination_mac[i]);
	        if( i!=5)
	            printf(":");
	    }
	    printf("\n");
	}
}ethernet;

typedef struct _ipv4{
	u_char source_ip[4];
	u_char destination_ip[4];

	void print(){
	    printf("source ip address : ");
	    for(int i=0; i<4; i++){
	        printf("%d", source_ip[i]);
	        if( i!=3)
	                printf(".");	
	    }
	    printf("\n");

	    printf("destination ip address : ");
	    for(int i=0; i<4; i++){
	        printf("%d", destination_ip[i]);
	        if( i!=3)
	                printf(".");
	    }
	    printf("\n");
	}
}ipv4;

typedef struct _ipv6{
	u_char source_ip[16];
	u_char destination_ip[16];

        void print(){
            printf("source ip address : ");
            for(int i=0; i<16; i++){
                printf("%c", source_ip[i]);
		printf("%c", source_ip[i+1]);
		i++;
		if(i != 15)
	               	printf(":");
            }
            printf("\n");

            printf("destination ip address : ");
	    for(int i=0; i<16; i++){
                printf("%c", destination_ip[i]);
                printf("%c", destination_ip[i+1]);
                i++; 
                if(i != 15)
                        printf(":");
            }
	}
}ipv6;


typedef struct _tcpH{
	u_char source_port[2];
	u_char destination_port[2];

	void print(){
	    printf("source port number : ");
	    printf("%d\n", (unsigned int)*source_port);

	    printf("destination port number : ");
	    printf("%d\n", (unsigned int)*destination_port);
	}

}tcpH;


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {

  //u_char smac[6], dmac[6];
  //u_char sip[4], dip[4];
  //u_char sport[2], dport[2];
  ethernet ether;
  ipv4 ip4;
  ipv6 ip6;
  tcpH tcph;
  u_char ipType;
  int ipLength;
  u_char dateLen, data[1430];


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
    
    // ether header
    memcpy(ether.destination_mac, &packet[0], 6);
    memcpy(ether.source_mac, &packet[6], 6);

    ether.print();

    // ip header
    memcpy(&ipType, &packet[ETHER_HEADER_LENGTH], 1);

    if( ((unsigned int)ipType / 16) == IPV4_NUM){
	    memcpy(ip4.source_ip, &packet[ETHER_HEADER_LENGTH + 12], 4);
	    memcpy(ip4.destination_ip, &packet[ETHER_HEADER_LENGTH + 16], 4);
	    ipLength = (unsigned int)ipType % 16 *4;

	    ip4.print();
    }
    else if(((unsigned int)ipType / 16) == IPV6_NUM){
    	    memcpy(ip6.source_ip, &packet[ETHER_HEADER_LENGTH + 8], 16);
            memcpy(ip6.destination_ip, &packet[ETHER_HEADER_LENGTH + 24], 16);
            ipLength = 40;
	    ip6.print();    
    }

    // tcp header

    memcpy(tcph.source_port, &packet[ETHER_HEADER_LENGTH + ipLength], 2);
    memcpy(tcph.destination_port, &packet[ETHER_HEADER_LENGTH + ipLength + 2], 2);
    
    tcph.print();
    
    
    memcpy(data, &packet[ETHER_HEADER_LENGTH + ipLength + TCP_HEADER_LENGTH], 16);
    
    printf("data : ");

    int data_size = (16 < (header->caplen - 54)) ? 16 : (header->caplen-54);

    for(int i=0; i< data_size ; i++){
	    printf("%x ", data[i]);
    }
    printf("\n\n");

  }

  pcap_close(handle);
  return 0;
}
