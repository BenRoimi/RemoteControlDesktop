#pragma once

#define IP_HDR_LEN 20
#define TCP_HDR_LEN 20
#define MAC_ADDR_LEN 6
#define IPV4_ADDR_LEN 4
#define ETHERNET_HEADER_LEN 14
#define ARP_PACKET_LEN 42

#define TCP_FLAG_FIN  0x01  // 0000 0001
#define TCP_FLAG_SYN  0x02  // 0000 0010
#define TCP_FLAG_RST  0x04  // 0000 0100
#define TCP_FLAG_PUSH 0x08  // 0000 1000
#define TCP_FLAG_ACK  0x10  // 0001 0000
#define TCP_FLAG_URG  0x20  // 0010 0000
#define TCP_FLAG_ECE  0x40  // 0100 0000
#define TCP_FLAG_CWR  0x80  // 1000 0000

#define ACK_FLAG 0x10
#define ACK_WAIT_TIME 3000

#define BUFFER 409

#define DEFAULT 0
#define ACCEPTCONNECTION 1
#define REGECTCONNECTION 2 

// TCP pseudo-header for checksum calculation
struct PseudoHeader {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

// Ethernet header struct
struct EthernetHeader {
    unsigned char dest_mac[MAC_ADDR_LEN];
    unsigned char src_mac[MAC_ADDR_LEN];
    unsigned short ethertype;
};

// IP header structure
struct IPHeader {
    unsigned char ver_ihl;           // Version and Header Length
    unsigned char tos;               // Type of Service
    unsigned short total_len;        // Total Length
    unsigned short identification;   // Identification
    unsigned short flags_offset;     // Flags and Fragment Offset
    unsigned char ttl;               // Time to Live
    unsigned char protocol;          // Protocol (TCP)
    unsigned short checksum;         // Header checksum
    unsigned int src_ip;             // Source IP Address
    unsigned int dest_ip;            // Destination IP Address
};

// TCP header structure
struct TCPHeader {
    unsigned short src_port;         // Source Port (2 bytes)
    unsigned short dest_port;        // Destination Port (2 bytes)
    unsigned int seq_num;            // Sequence Number (4 bytes)
    unsigned int ack_num;            // Acknowledgment Number (4 bytes)
    unsigned char data_offset;       // Data Offset (4 bits) + Reserved (3 bits), 1 byte total
    unsigned char flags;             // Flags (6 bits), 1 byte total
    unsigned short window_size;      // Window Size (2 bytes)
    unsigned short checksum;         // Checksum (2 bytes)
    unsigned short urgent_ptr;       // Urgent Pointer (2 bytes)
};

// ARP header struct
struct ArpHeader {
    unsigned short hwType;
    unsigned short protocolType;
    unsigned char hwSize;
    unsigned char protocolSize;
    unsigned short opcode;
    unsigned char senderMAC[MAC_ADDR_LEN];
    unsigned char senderIP[IPV4_ADDR_LEN];
    unsigned char targetMAC[MAC_ADDR_LEN];
    unsigned char targetIP[IPV4_ADDR_LEN];
};


struct UDPHeader {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
};
