#ifndef __ETH_2_CAN_H__
#define __ETH_2_CAN_H__

/* structure for can data */

struct CanHeadFromID{
	unsigned int cseq		:8;
	unsigned int eseq		:3;
	unsigned int type		:2;
	unsigned int node		:8;
	unsigned int reserved	:8;
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
	CanTxMsg canPacket;
	struct queueCSend *nextPtr;
};

typedef struct queueCSend QUEUECSEND;
typedef QUEUECSEND* QUEUECSENDPTR;

QUEUECSENDPTR queueCSendHeadPtr=NULL, queueCSendTailPtr=NULL;


# endif  /* __ETH_2_CAN_H__ */