/* Simple Sniffer                           */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include "eth2can.h"

#define MAXBYTES2CAPTURE 2048

/* enqueue can packet to send */
void enqueue_CSend(QUEUECSENDPTR newQueueCSendPtr){
	
	if ( newQueueCSendPtr != NULL ){
	    newQueueCSendPtr->nextPtr = NULL;
	 }
	else {
		printf("ERR: enqueue_CSend, newQueueCSendPtr == NULL\n");
	    return;
	}

	if ( queueCSendHeadPtr == NULL ) {
		queueCSendHeadPtr = newQueueCSendPtr;
	}
	else {
		queueCSendTailPtr->nextPtr = newQueueCSendPtr;
	}

	queueCSendTailPtr = newQueueCSendPtr;
}

/* print the data in queue */
void printQueueCSend(){

	QUEUECSENDPTR currentQueueCSendPtr=NULL;

	currentQueueCSendPtr = queueCSendHeadPtr;
	
	if ( currentQueueCSendPtr == NULL ){
		printf("queueCSend is empty.\n");
	}
	else {
		printf("queueCSend:\n");
		while ( currentQueueCSendPtr != NULL ){

			printf("%.8x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x \n", \
				currentQueueCSendPtr->canPacket.ExtId,   \
				currentQueueCSendPtr->canPacket.Data[0], \
				currentQueueCSendPtr->canPacket.Data[1], \
				currentQueueCSendPtr->canPacket.Data[2], \
				currentQueueCSendPtr->canPacket.Data[3], \
				currentQueueCSendPtr->canPacket.Data[4], \
				currentQueueCSendPtr->canPacket.Data[5], \
				currentQueueCSendPtr->canPacket.Data[6], \
				currentQueueCSendPtr->canPacket.Data[7]);

			currentQueueCSendPtr = currentQueueCSendPtr->nextPtr;
		}

	}
}

/*
 * print every received packet
 */
void processPrintEPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    
    uint32_t i=0, *counter = (uint32_t *)arg;

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
    
    uint32_t i=0, j=0, *counter = (uint32_t *)arg;

	union CanID canid_tmp;
	QUEUECSENDPTR newQueueCSendPtr=NULL;

	canid_tmp.ExtId = 0;
	canid_tmp.canhead.eseq = ++(*counter)%8;

    /* first Can Packet */
	newQueueCSendPtr = (QUEUECSENDPTR)malloc(sizeof(QUEUECSEND));
	if (newQueueCSendPtr == NULL ){
       printf("ERR: processSliptE2CPacket, newQueueCSendPtr == NULL\n");
	   return;
	}

	canid_tmp.canhead.cseq = 0;
	/* calculate the assumedNum of Can Packet */
	if ( pkthdr->len <= 7 ){
		newQueueCSendPtr->canPacket.Data[0] = 1;
	}
	else {
       newQueueCSendPtr->canPacket.Data[0] = 1 + (pkthdr->len - 7)/8;
	   if ( (pkthdr->len-7)%8 > 0 ){
		   newQueueCSendPtr->canPacket.Data[0] += 1;
	   }
	}
    
	for (i=0; i<7; i++) {
		newQueueCSendPtr->canPacket.Data[i+1] = packet[i];
	}

	newQueueCSendPtr->canPacket.ExtId = canid_tmp.ExtId;
	enqueue_CSend(newQueueCSendPtr);

    /* the second, 3rd, 4th..... */
	while ( i < pkthdr->len ) {

		newQueueCSendPtr = (QUEUECSENDPTR)malloc(sizeof(QUEUECSEND));
		if (newQueueCSendPtr == NULL ){
			printf("ERR: processSliptE2CPacket, while loop, newQueueCSendPtr == NULL\n");
			return;
		}

		canid_tmp.canhead.cseq++;

		for (j=0; ( j<8 ) && ( i< (pkthdr->len) ); j++) {
			newQueueCSendPtr->canPacket.Data[j] = packet[i];
			i++;
		}

		newQueueCSendPtr->canPacket.ExtId = canid_tmp.ExtId;
		enqueue_CSend(newQueueCSendPtr);

	}

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

	printQueueCSend();

	getchar();
    return 0; 
}