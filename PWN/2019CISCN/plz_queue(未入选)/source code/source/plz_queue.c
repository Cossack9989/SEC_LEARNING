//gcc plz_queue.c -o pwn -s -fstack-protector -fPIC -pie -Wl,-z,relro -Wl,-z,now
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>

typedef struct Message{
	int size;
	char* data;
}Msg; 
typedef struct Queue{
	Msg **msg;
	unsigned int size;
	int front;
	int rear;
}Q;

#define POLY64REV     0x95AC9329AC4BC9B5ULL
#define INITIALCRC    0xFFFFFFFFFFFFFFFFULL
unsigned long long CRCTable[256];
unsigned int proof;
void crc64(char *seq, char *res)
{
    int i, j, low, high;
    static unsigned long long crc = INITIALCRC, part;
    int init = 0;
    
    if (!init)
    {
	init = 1;
	for (i = 0; i < 256; i++)
	{
	    part = i;
	    for (j = 0; j < 8; j++)
	    {
		if (part & 1)
		    part = (part >> 1) ^ POLY64REV;
		else
		    part >>= 1;
	    }
	    CRCTable[i] = part;
	}
    }
    
    while (*seq)
	crc = CRCTable[(crc ^ *seq++) & 0xff] ^ (crc >> 8);

    /* 
     The output is done in two parts to avoid problems with 
     architecture-dependent word order
     */
    low = crc & 0xffffffff;
    high = (crc >> 32) & 0xffffffff;
    sprintf (res, "%08X%08X", high, low);

    return;
}
void POW(){
	char buf[0x8];
	char buf2[0x8];
	char chk[0x8];
	memset(buf,0,8);
	int fd = open("/dev/urandom",O_RDONLY);
	read(fd,buf,0x8);
	buf[7]=0;
	crc64(buf,buf2);
	printf("%s check:",buf2);
	read(0,chk,0x8);
	if(!strncmp(buf,chk,8)){proof++;puts("Proof done");}
	return;
}

Msg* newMsg(){
	Msg* m;
	unsigned int size;
	m = (Msg*)malloc(sizeof(Msg));if(m == NULL)exit(1);
	printf("MSG SIZE : ");
	scanf("%u",&size);
	getchar();
	if(size == 0 || size > 12)exit(1);
	m->size = size;
	m->data = (char*)malloc(m->size);if(m->data == NULL)exit(1);
	printf("MSG DATA : ");
	read(0,m->data,m->size);
	return m;
}
void delMsg(Msg* imsg){
	free(imsg->data);
	imsg->data = NULL;
	free(imsg);
	imsg = NULL;
}

Q* initQ(){
	Q* iq;
	unsigned int size;
	iq = (Q*)malloc(sizeof(Q));if(iq == NULL)exit(1);
	printf("QUEUE SIZE : ");
	scanf("%u",&size);
	getchar();
	if(size == 0 || size >= 4)exit(1);
	iq->size = size;
	iq->msg = (Msg**)malloc(sizeof(Msg*)*iq->size);if(iq->msg == NULL)exit(1);
	iq->front = 0;
	iq->rear = 0;
	return iq;
}

void enQ(Q* iq, Msg* imsg){
	if((iq->rear+1)%iq->size == iq->front){printf("FULL\n");return;}
	else{
		iq->msg[iq->rear] = imsg;
		iq->rear = (iq->rear+1)%(iq->size);
		printf(imsg->data);
		printf("enqueue!\n");
	}
}
void deQ(Q* iq){
	if((iq->front == iq->rear)){printf("EMPTY\n");return;}
	else{
		if(proof--){
		printf("%s dequeue!\n",iq->msg[iq->front]->data);
		delMsg(iq->msg[iq->front]);
		iq->front = (iq->front+1)%(iq->size);
		}else{printf("You need more proof.");}
	}
}


Q* welcome(){
	setbuf(stdin,NULL);
	setbuf(stdout,NULL);
	setbuf(stderr,NULL);
	return initQ();
}

int getChoice(){
	char buf[9];
	printf("1.enQueue\n2.deQueue\n3.ProofYourself\n4.bye\n>> ");
	read(0,buf,9);
	return atoi(buf);
}

int main(){
	Q* x = welcome();
	while(1){
		switch(getChoice()){
			case 1:
				enQ(x,newMsg());
				break;
			case 2:
				deQ(x);
				break;
			case 3:
				POW();
				break;
			default:
				exit(1);
		}
	}
}
