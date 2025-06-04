#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <array>
#include <pcap.h>
#include "NetworkHeaders_Structures.h"

/**
 * Class: Connection
 * ------------------
 * Handles the setup and configuration of raw network communication using Npcap.
 * Manages socket setup, MAC address retrieval (local and remote), and interface selection.
 */
class Connection {
  protected:
    // Setup funcitons
    bool configureSocket();
    bool configureSocket(Connection *other);

    // Mac address functions
    void GetMacAddress(unsigned char* mac, in_addr destip);
    bool GetLocalMacAddress(unsigned char* mac);

    // Connection Info
    int srcPort; ///< Source port used for outgoing packets
    int dstPort; ///< Destination port used for incoming packets
    std::string DstIpAddress; ///< Destination IP address (string format)
    std::string SrcIpAddress; ///< Source IP address (string format)
    unsigned char dest_mac[MAC_ADDR_LEN]; ///< Destination MAC address
    unsigned char src_mac[MAC_ADDR_LEN]; ///< Source MAC address

    // Npcap info
    pcap_if_t* alldevs; ///< Pointer to the list of all available devices
    char errbuf[PCAP_ERRBUF_SIZE]; ///< Buffer to hold error messages from pcap functions
    pcap_t* handle = nullptr; ///< Handle to the opened device for capturing/sending packets
    const char* selected_device; ///< Name of the selected network interface

public:
    bool foundDestMac = false;
    std::array<unsigned char, MAC_ADDR_LEN> getDestMac() const;
};