#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
#include<iostream>
using namespace std;

/* IP Header */
struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4;           // IP Header length & Version.
    unsigned char iph_tos;                            // Type of service
    unsigned short int iph_len;                       // IP Packet length (Both data and header)
    unsigned short int iph_ident;                     // Identification
    unsigned short int iph_flag : 3, iph_offset : 13; // Flags and Fragmentation offset
    unsigned char iph_ttl;                            // Time to Live
    unsigned char iph_protocol;                       // Type of the upper-level protocol
    unsigned short int iph_chksum;                    // IP datagram checksum
    struct in_addr iph_sourceip;                      // IP Source address (In network byte order)
    struct in_addr iph_destip;                        // IP Destination address (In network byte order)
};

/* ICMP Header */
struct icmpheader {
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used in echo request/reply to identify request
    unsigned short int icmp_seq;    // Identifies the sequence of echo messages,
                                    // if more than one is sent.
};

struct headerpair {
    struct ipheader iph;
    struct icmpheader icmph;
};

#define ICMP_ECHO_REPLY     0
#define ICMP_ECHO_REQUEST   8
#define ICMP_TIME_EXCEEDED  11
#define MAX_HOPS            30
#define MAX_RETRY           3
#define PACKET_LEN          1500

void traceroute(char* dest) {
    // raw sockets require root priviliges: no change necessary
    if (getuid() != 0) {
        perror("requires root privilige");
        exit(-1);
    }

    // open socket: no change necessary
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(-1);
    }

    // dns resolve and get ip for destination: no change necessary
    sockaddr_in addr;
    memset(&addr, 0, sizeof(sockaddr_in));
    addr.sin_family = AF_INET;
    hostent* getip = gethostbyname(dest);
    if (getip == NULL) {
        perror("failed gethostbyname");
        exit(-1);
    }
    memcpy((char*)(&addr.sin_addr), getip->h_addr, getip->h_length);

    printf("traceroute to %s (%s), %d hops max, %ld bytes packets\n", dest, inet_ntoa(addr.sin_addr), MAX_HOPS, sizeof(ipheader) + sizeof(icmpheader));
    
    char send_buf[PACKET_LEN], recv_buf[PACKET_LEN];

    for(int ttl = 1; ttl <= MAX_HOPS; ) {
        printf("%2d ", ttl);
        // set ttl to outgoing packets: no need to change
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) < 0) {
            perror("setsockopt failed");
            exit(-1);
        }

        int retry = 0;
        while(true) {
            // prepare ICMP packet
            /** TODO: 1
             * Prepare packet
             * a. outgoing packets only contain the icmpheader with type = ICMP_ECHO_REQUEST, code = 0
             * b. ID in the icmpheader should be set to current process id to identify received ICMP packets
             * c. checksum can be set to 0 for this test
             * d. write/copy the header to the send_buf  
             * 
             * HINT:
             * - icmpheader* icmp = (icmpheader*)send_buf;
             * - set header fields with required values: icmp->field = value;
             * */
            // prepare outgoing packets
            icmpheader* icmp = (icmpheader*) send_buf;
            icmp->icmp_type = ICMP_ECHO_REQUEST;
            icmp->icmp_code = 0;
            unsigned short int pid = (unsigned short int) getpid();
            icmp->icmp_id = pid;
            icmp->icmp_chksum = 0;
            /** TODO: 2
             * set the seq in icmpheader to ttl
             * 
             * HINT:
             * similar to TODO 1 HINT, just set the seq
             */
            // update ttl of outgoing packet
            icmp->icmp_seq = ttl;
            /** TODO: 3
             * send packet using sendto(...)
             * 
             * HINT:
             * - check man page of sendto(...)
             * - ensure we send one icmpheader in the packet
             * 
             */
            if(sendto(sockfd, send_buf, sizeof(icmpheader), 0, (sockaddr*)&addr, sizeof(addr)) != sizeof(icmpheader)) {
                perror("packet didn't have exactly one icmpheader");
                exit(-1);
            }

            socklen_t addr_len = sizeof(addr);
            getpeername(sockfd, (struct sockaddr*) &addr, &addr_len);

            // Print the destination address and port
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
            printf("Destination address: %s\n", ip_str);
            printf("Destination port: %d\n", ntohs(addr.sin_port));

            timeval tv;
            fd_set rfd;
           
            // wait to check if there is data available to receive; need to retry if timeout: no need to change
            tv.tv_sec = 1;
            FD_ZERO(&rfd);
            FD_SET(sockfd, &rfd);
            int ret = select(sockfd + 1, &rfd, NULL, NULL, &tv);
            if(ret == 0) {
                // resend message
                if(sendto(sockfd, (char*)icmp, sizeof(icmpheader), 0, (sockaddr*)&addr, sizeof(addr)) != sizeof(icmpheader)) {
                    perror("packet didn't have exactly one icmpheader");
                    exit(-1);
                }

                // print attempt
                cout << "* ";
                retry++;
            } else if(ret > 0) {
                struct ipheader *ip = (struct ipheader*) recv_buf;
                struct icmpheader *icmp = (struct icmpheader*) (recv_buf + sizeof(struct ipheader));
                struct ipheader *ip2 = (struct ipheader*) (recv_buf + sizeof(struct ipheader) + sizeof(struct icmpheader));
                struct icmpheader *icmp2 = (struct icmpheader*) (recv_buf + (2*sizeof(struct ipheader)) + sizeof(struct icmpheader));

                socklen_t addr_len = sizeof(addr);
                ssize_t bytes_read = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&addr, &addr_len);
                if(bytes_read <= 0) {
                    perror("no data read from recvfrom()");
                    exit(-1);
                }
                struct ipheader ip_hdr;
                memcpy(&ip_hdr, ip, sizeof(struct ipheader));
                struct icmpheader icmp_hdr;
                memcpy(&icmp_hdr, icmp, sizeof(struct icmpheader));

                // get type and pid
                unsigned char type = icmp_hdr.icmp_type;
                char* router_ip;
                router_ip = inet_ntoa(ip_hdr.iph_sourceip);

                // evaluate bytes read by recvfrom()
                if(bytes_read >= 2 * (sizeof(ipheader) + sizeof(icmpheader))) {  
                    // create second set of headers
                    struct ipheader ip_hdr2;
                    memcpy(&ip_hdr2, ip2, sizeof(struct ipheader));
                    struct icmpheader icmp_hdr2;
                    memcpy(&icmp_hdr2, icmp2, sizeof(struct icmpheader)); 

                    // check between header pairs 
                    // && icmp_hdr.icmp_seq == icmp_hdr2.icmp_seq && icmp_hdr.icmp_id == icmp_hdr2.icmp_id
                    if(type == ICMP_TIME_EXCEEDED) {
                        // print router ip
                        cout << router_ip;
                        ttl++;
                        break;
                    } else {
                        cout << "whomp";
                    }
                } else if(type == ICMP_ECHO_REPLY) {
                    // print router ip
                    cout << router_ip << endl;
                    // exit
                    return;
                }
            }
            fflush(stdout);
            if(retry == MAX_RETRY) {
                ttl++;
                break;
            }
        }
        cout << endl;
    }
    close(sockfd);
}

int main(int argc, char** argv) {

    if (argc < 2) {
        printf("Usage: traceroute <destination hostname>\n");
        exit(-1);
    }
    
    char* dest = argv[1];
    traceroute(dest);

    return 0;
}