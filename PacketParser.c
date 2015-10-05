/*
   ========================================================================================================
     Title  - Network Packet Parser
        ---------------------------------------------------------------------------------------------------
     Date   - 5th June 2014
        ---------------------------------------------------------------------------------------------------
     Brief Description

     -This is a menu driver program wherein you get the summary of all the packets or a single packet
     for inspection. 
     -Separate modules have been created to display the details of each header.
      -----------------------------------------------------------------------------------------------------
     Note

     -This code works for both the tcp.pcap and the arp.pcap files.
     -The name of the file has to been as a command line argument
   =========================================================================================================
*/

#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <time.h>

//Header sizes for display purposes 
#define ETHER_HEADERSIZE 14
#define ARP_HEADERSIZE 28
//Pre-Calculated TCP Header Offset 
#define TCPHDROFFSET(th)  (((th)->dataoffset & 0xf0) >> 4)
            
/*
    ===============================================================================
    Structures to parse the headers in the pcap files - Ethernet, IP, TCP and ARP
    ===============================================================================
*/

typedef struct ether 
{
    unsigned char desthost[6]; 
    unsigned char srchost[6];  
    unsigned short type;       // IP or ARP
}ether;

typedef struct IP 
{
    unsigned char headlen;    //Holds the version << 4 and the header length >> 2 
    unsigned char tos;        //Type of Service
    unsigned short totlen;     
    unsigned short ident;      
    unsigned short offset;    //Fragment Offset Field */
    unsigned char ttl;        //Time to Live */
    unsigned char protocol;   
    unsigned short ipchecksum;     
    struct in_addr sourceip;
    struct in_addr destip;     
}IP;
  
typedef struct TCP
{
    unsigned short srcport;   
    unsigned short destport;   
    uint32_t seqno;           
    uint32_t ackno;            
    unsigned char dataoffset;    
    unsigned char flags;
    unsigned short  window;     
    unsigned short  tcpchecksum;     
    unsigned short  urgptr;     
}TCP;

typedef struct ARP 
{ 
    uint16_t hwtype;             
    uint16_t prottype;            
    unsigned char hwaddrlen;         
    unsigned char protlen;         
    uint16_t oper;                       
    unsigned char shwaddr[6];      // Sender hardware address  
    unsigned char sipaddr[4];      // Sender IP address        
    unsigned char thwaddr[6];      // Target hardware address 
    unsigned char tipaddr[4];      // Target IP address       
}ARP;


/*
     ================================
      Function Prototypes       
     ================================
*/
unsigned short dispetherdetails(const unsigned char *);
int dispipdetails(const unsigned char *);
int disptcpdetails(const unsigned char *, int );
void disparpdetails(const unsigned char *);
void printdata(int ,int ,const unsigned char *, int );
void parser(int ,char *);

/*
     ================================
      Main Function       
     ================================
*/
int main(int argc, char *argv[])
{
    //File name is sent as an argument
    char *file = argv[1];
    int choice=0,pno=0; 
   
   //Display the menu and take the user's choice 
    while(1)
    {
        pno=0;
        printf("\n--Network Packet Parser--\n");
        printf("\nPress 1 for the Full Summary");
        printf("\nPress 2 for Selected Packet Summary");
        printf("\nPress 3 to exit");
        printf("\nChoice -- > ");
        scanf("%d",&choice);
        if(choice==2)
        {
            printf("\nEnter the packet number: ");
            scanf("%d",&pno);
        }
        if(choice==3)
            exit(0);
        parser(pno,file);
    }
    return 0;
} 

/*
     ============================================================================================
     Function Objective - Parses the data and displays each packet's details
        -----------------
     Parameters         - (1)Packet No to be printed(default 0 for all packets to be printed), 
                          (2)PCap file name
        -----------------
     Return Value       - None 
     ============================================================================================
*/
void parser(int pno,char *file)
{
    
    //Create a packet header and a data object
    struct pcap_pkthdr *header;
    const unsigned char *data;
    
    //Variable Declarations
    unsigned short ethertype;
    struct tm *info;
    char actualtime[80];
    int i;
    int ipheadlen,tcpheadlen;
    int pktctr = 1,val;

    //Char array to hold the error. PCAP_ERRBUF_SIZE is defined as 256.
    char errbuff[PCAP_ERRBUF_SIZE];
 
    //Open the saved captured file and store result in pointer to pcap_t
    pcap_t *pcap = pcap_open_offline(file, errbuff);
 
    //Start reading packets one by one 
    while (val = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        
        //To find a particular packet to be displayed
        if(pno!=0)
        {
            while (pktctr!=pno)
            {
                val = pcap_next_ex(pcap, &header, &data);
                if(val >= 0)
                    pktctr++;
            }
        }

        
        printf("*******************************************************\n");
        printf("\n\t\t--PACKET INFO--\n\n");
        
        // Show the packet number
        printf("Packet\t# %d\n", pktctr++);
        printf("Packet size\t: %d bytes\n", header->len);
        
        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %u bytes\n", header->len);
        
        //Conversion of Epoch Time into readable format
        info = localtime(&header->ts.tv_sec);
        strftime(actualtime,80,"%c",info);
        printf("Epoch Time\t: %lu:%lu seconds | %s\n\n", header->ts.tv_sec, header->ts.tv_usec,actualtime);
    
        ethertype=dispetherdetails(data);
        
        /*
            Display IP and TCP details for tcp.pcap file
            or display ARP details for arp.pcap file
        */
        if(ethertype==8)
        {
            ipheadlen = dispipdetails(data);
            tcpheadlen=disptcpdetails(data,ipheadlen); 
                 
            //Systematic display of the data dump   
            printf("\n\t\t--DUMP--\n");
            printf("\n--IP HEADER--");
            printdata(ETHER_HEADERSIZE,ETHER_HEADERSIZE+ipheadlen,data,0);
            printf("\n--TCP HEADER--");
            printdata(ETHER_HEADERSIZE+ipheadlen,ETHER_HEADERSIZE+ipheadlen+tcpheadlen,data,0);
            printf("\n--DATA PAYLOAD--");
            printdata(ETHER_HEADERSIZE+ipheadlen+tcpheadlen,header->caplen,data,1);
        }
        else if(ethertype==1544)
        {
            disparpdetails(data);

            printf("\n\t\t--DUMP--\n");
            printf("\n--ARP HEADER--");
            printdata(ETHER_HEADERSIZE,ETHER_HEADERSIZE+ARP_HEADERSIZE,data,0);
            printf("\n--DATA PAYLOAD--");
            printdata(ETHER_HEADERSIZE+ARP_HEADERSIZE,header->caplen,data,1);

        }
        if(pno!=0)
            break;
          
        // Add two lines between packets
        printf("\n\n");
    }
    printf("\n*******************************************************\n");
}


/*
   =============================================================
    Functions to display the headers details
   =============================================================
    
   =============================================================
     Function Objective - Displays ethernet header details
        -----------------
     Parameter          - PCap Packet Data
        -----------------
     Return Value       - Ethernet Type(IP/ARP) 
   =============================================================
*/
unsigned short dispetherdetails(const unsigned char *data)
{
    ether *ethernet;
    ethernet = (ether*)(data);
    int i,flag;
    printf("\t\t--ETHERNET HEADER INFO--\n\n");

    printf("Source MAC Address\t: ");
    for(i=0; i<6;i++)
        printf("%02X:", ethernet->srchost[i]); 
    
    printf("\nDestination MAC Address\t: ");
    for(i=0; i<6;i++)
    {  
        printf("%02X:", ethernet->desthost[i]); 
        if(ethernet->desthost[i]==255)
            flag=1;
        else
            flag=0;
    }
    // If MAC Address is FF:FF:FF:FF:FF:FF it is for Broadcast
    if(flag==1)
        printf("  (Broadcast)");

    // ether_type for IP is 0x0800 or 8 in decimal and for ARP it is 0x0806 or 1544 in decimal
    if(ethernet->type==8)
        printf("\nFrame Type\t\t: IP\n");
    else if(ethernet->type==1544)
        printf("\nFrame Type\t\t: ARP\n");

    return ethernet->type;

}

/*
   ======================================================
     Function Objective - Displays IP header details
        -----------------
     Parameter          - PCap Packet Data
        -----------------
     Return Value       - IP header length 
   ======================================================
*/

int dispipdetails(const unsigned char *data)
{
    IP *ip;
    char srcname[20],dstname[20];

    //Point to the IP header i.e. 14 bytes(Size of ethernet header) from the start 
    ip = (IP*)(data + ETHER_HEADERSIZE);

    printf("\n\t\t--IP HEADER INFO--\n\n");
    strcpy(srcname,inet_ntoa(ip->sourceip));
    strcpy(dstname,inet_ntoa(ip->destip));
    printf("Source IP\t: %s\nDestination IP\t: %s \n",srcname ,dstname);
    printf("Header Length\t: %d Bytes\n",((unsigned int)(ip->headlen))*4);

    if(ip->tos==0)
        printf("Type Of Service\t:(0) Routine\n");
    else if(ip->tos==1)
        printf("Type Of Service\t:(1) Priority\n");
    else if(ip->tos==2)
        printf("Type Of Service\t:(2) Immediate\n");
    else if(ip->tos==3)
        printf("Type Of Service\t:(3) Flash\n");
    else if(ip->tos==4)
        printf("Type Of Service\t:(4) Flash Override\n");
    else if(ip->tos==5)
        printf("Type Of Service\t:(5) CRITIC/ECP\n");
    else if(ip->tos==7)
        printf("Type Of Service\t:(7) Network Control\n");
    else if(ip->tos==6)
        printf("Type Of Service\t:(6) Internetwork Control");

    printf("Identification\t: %d\n",ntohs(ip->ident));
    printf("TTL\t\t: %d\n",(unsigned int)ip->ttl);
    if((unsigned int)(ip->protocol)==6)
        printf("Protocol\t: TCP (6)\n");
    printf("Checksum\t: %d\n",ntohs(ip->ipchecksum));


    /* Calculation of IP Header Length
        
        1)In this case ip->headlen contains 45 where 4 is the IP version and 5 is the actual length
        2)We only need the length so masking with 0x0f is done
        3)This length is in Byte Words so multiplication with 4 gives us the length in bytes
    */
    return ((ip->headlen & 0x0f)*4); 
}

/*
    
   =============================================================
     Function Objective - Displays TCP header details
        -----------------
     Parameters         - PCap Packet Data , IP header length
        -----------------
     Return Value       - TCP header length 
   =============================================================
*/

int disptcpdetails(const unsigned char *data, int ipheadlen)
{
    TCP *tcp;
    unsigned short srcport,dstport;
    
    //Point to the TCP header as explained in IP
    tcp = (TCP*)(data + ETHER_HEADERSIZE + ipheadlen);
   
    printf("\n\t\t--TCP HEADER INFO--\n\n");

    printf("Source Port\t: %d\nDestination Port: %d \n", ntohs(tcp->srcport), ntohs(tcp->destport));
    printf("SEQ Number\t: %u\nACK Number\t: %u \n", ntohl(tcp-> seqno), ntohl(tcp->ackno));
    printf("Header Length\t: %d Bytes\n",(unsigned int)(TCPHDROFFSET(tcp)*4));
    printf("Window\t\t: %d\n",ntohs(tcp->window));
    printf("Checksum\t: %d\n",ntohs(tcp->tcpchecksum));

    /*Calculation of TCP Header Length 
        1)Byte Offset 12 is TCP HDR LEN
        2)Format is 50 or similar
        3)We need the MSB so masking with 0xf0 is done and the right shifting by 4 bits(>>4)
        4)Now multiplication with 4 done to get length in bytes  
    */

    return (TCPHDROFFSET(tcp)*4);
}

/*
    
   ======================================================
     Function Objective - Displays ARP header details
        -----------------
     Parameter          - PCap Packet Data 
        -----------------
     Return Value       - None 
   ======================================================
*/

void disparpdetails(const unsigned char *data)
{
 
    ARP *arp;
    int i;
    
    // Point to the ARP header 
    arp = (ARP*)(data+ETHER_HEADERSIZE); 
 
    printf("\n\t\t--ARP HEADER INFO--\n\n");
    if(ntohs(arp->hwtype) == 1)
        printf("Hardware type\t\t\t\t: Ethernet (0001)\n"); 
    if(ntohs(arp->prottype) == 0x0800)
        printf("Protocol type\t\t\t\t: IPv4 (0800)\n");
    printf("Link Layer Hardware Address Length\t: %d Bytes\n",(unsigned int)(arp->hwaddrlen));
    printf("Network Protocol Address Length\t\t: %d Bytes\n",(unsigned int)(arp->protlen));
    if(ntohs(arp->oper)==1)
        printf("Operation\t\t\t\t: ARP Request\n");
    else
        printf("Operation\t\t\t\t: ARP Reply\n"); 

    // If Hardware type is Ethernet and Protocol is IPv4, print packet contents  
    if (ntohs(arp->hwtype) == 1 && ntohs(arp->prottype) == 0x0800)
    { 
         
        printf("Sender Hardware Address\t\t\t: "); 
        for(i=0; i<6;i++)
            printf("%02X:", arp->shwaddr[i]);
    
        printf("\nTarget Hardware Address\t\t\t: "); 
        for(i=0; i<6;i++)
            printf("%02X:", arp->thwaddr[i]); 
        
        printf("\nSender Network Protocol Address\t\t: "); 
        for(i=0; i<4;i++)
            printf("%d.", arp->sipaddr[i]); 

        printf("\nTarget Network Protocol Address\t\t: "); 
            for(i=0; i<4; i++)
            printf("%d.", arp->tipaddr[i]); 

        printf("\n"); 
    }    

}

/*
   ==========================================================================================================
     Function Objective - Displays the PCap packet data
        -----------------
     Parameters         - (1)Start byte for printing, (2)End byte to stop printing, 
                          (3)PCap Packet Data, (4)Flag is 0 to print in hex or 1 to print in readable form 
        -----------------
     Return Value       - None 
   ==========================================================================================================
*/
void printdata(int offset,int size,const unsigned char *data, int flag)
{
    int i,j;
    
    for (i=offset,j=0; (i < size) ; i++,j++)
    {
        // Start printing on the next after every 16 octets
        if ( (j % 16) == 0) 
            printf("\n");
        if(flag==1)
        {
            //Check if the packet data is printable
            if(isprint(data[i]))                
                printf(" %c ",data[i]);
            else
               printf(" . ",data[i]); 
        }
        else
            printf(" %.2x",data[i]);          
    }
}


