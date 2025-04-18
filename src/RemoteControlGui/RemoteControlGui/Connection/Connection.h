#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <array>
#include <pcap.h>
#include "NetworkHeaders_Structures.h"

class Connection {
  protected:
    bool configureSocket();
    bool configureSocket(Connection *other);

    // Mac info functions
    void GetMacAddress(unsigned char* mac, in_addr destip);
    bool GetLocalMacAddress(unsigned char* mac);

    // Connection Info
    int srcPort;
    int dstPort;
    std::string DstIpAddress;
    std::string SrcIpAddress;
    unsigned char dest_mac[MAC_ADDR_LEN];
    unsigned char src_mac[MAC_ADDR_LEN];

    // Npcap info
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;
    const char* selected_device;
public:
    bool foundDestMac = false;
    std::array<unsigned char, MAC_ADDR_LEN> getDestMac() const;
};