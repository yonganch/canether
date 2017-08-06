/* Simple Sniffer                           */

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* structure for can data */
struct CanHeadFromID{
	unsigned int reserved	:8;
	unsigned int node		:8;
	unsigned int type		:2;
	unsigned int eseq		:3;
	unsigned int cseq		:8;
};

union CanID{
	struct CanHeadFromID canhead;
	uint32_t ExtId;	
};

typedef struct
{
  uint32_t StdId;  
  uint32_t ExtId;  
  uint8_t  IDE;     
  uint8_t  RTR;     
  uint8_t  DLC;     
  uint8_t  Data[8];
} CanTxMsg;

struct queueCSend{
	CanTxMsg canpacket;
	struct queueCSend *next;
};


#define MAXBYTES2CAPTURE 2048

/*
 * print every received packet
 */
void processPrintEPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    
    int i=0, *counter = (int *)arg;

    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("payload:\n");
	
    for (i=0; i<pkthdr->len; i++){

		/*
        if ( isprint(packet[i]) )
			printf("%c ", packet[i]);
		else
			printf(". ");
		*/

		printf("%.2x ", packet[i]);
		
		if( (i+1)%16 == 0 || i == pkthdr->len-1 ){

			printf("\n");
		}

    }

	printf("\n");
    return;
}

/*
 * slipt ethernet Packet to can packet
 */
void processSliptE2CPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    
    int i=0, *counter = (int *)arg;
	

    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->len);

    return;
}

int main(){

    int i=0, count=0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    
    /* Get the name of the first device suitable for capture */
    /* device = pcap_lookupdev(errbuf);                      */

    /* printf("Opening device %s\n", device);                */

    /* Open device in promiscuous mode */
    /* descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf); */

	descr = pcap_open_offline("cap.pcap", errbuf);

	if ( descr==NULL ) {

        printf("%s\n", errbuf);

		getchar();
		return 0;
	}

    /* Loop forever for every received packet */
    pcap_loop(descr, -1, processSliptE2CPacket, (u_char *)&count);

	getchar();
    return 0; 
}