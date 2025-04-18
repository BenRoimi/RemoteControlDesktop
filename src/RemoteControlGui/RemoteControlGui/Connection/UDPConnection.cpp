#include "UDPConnection.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <cstring>
#include <iostream>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

UDPConnection::UDPConnection()
{
}

// Constructor
UDPConnection::UDPConnection(int srcPort, int dstPort)
    : srcPort(srcPort), dstPort(dstPort) {
    configureSocket();
}

// Constructor with IP
UDPConnection::UDPConnection(int srcPort, int dstPort, const std::string& ipaddress)
    : srcPort(srcPort), dstPort(dstPort), ipAddress(ipaddress) {
    configureSocket();
    in_addr destip;
    if (inet_pton(AF_INET, ipAddress.c_str(), &destip) != 1) {
        std::cerr << "Invalid IP address format." << std::endl;
        return;
    }
    GetMacAddress(dest_mac, destip);
}

UDPConnection::UDPConnection(int srcPort, int dstPort, Connection* other) : srcPort(srcPort), dstPort(dstPort) {
    configureSocket(other);
}

UDPConnection::UDPConnection(int srcPort, int dstPort, const std::string& ipaddress, Connection* other)
    : srcPort(srcPort), dstPort(dstPort), ipAddress(ipaddress) {
    configureSocket(other);
    in_addr destip;
    if (inet_pton(AF_INET, ipAddress.c_str(), &destip) != 1) {
        std::cerr << "Invalid IP address format." << std::endl;
        return;
    }

    if (other->foundDestMac) {
        std::array<unsigned char, MAC_ADDR_LEN> mac = other->getDestMac();
        std::copy(mac.begin(), mac.end(), dest_mac);
        foundDestMac = true;
    }
    else {
        GetMacAddress(dest_mac, destip);
    }
}

// Close connection
void UDPConnection::closeConnection() {
    if (handle != nullptr) {
        pcap_close(handle);
        handle = nullptr;
    }
    pcap_freealldevs(alldevs);
}

bool UDPConnection::sendData(const std::vector<uint8_t>& data)
{
    // Total packet size calculation
    size_t packetSize = sizeof(UDPHeader) + IP_HDR_LEN + ETHERNET_HEADER_LEN + data.size();
    std::vector<unsigned char> packet(packetSize);

    // Fill in the packet here, similar to how you would with a static array
    unsigned char* packetPtr = packet.data();

    // Ethernet header
    EthernetHeader* ethHeader = reinterpret_cast<EthernetHeader*>(packetPtr);
    memcpy(ethHeader->dest_mac, this->dest_mac, MAC_ADDR_LEN);
    memcpy(ethHeader->src_mac, this->src_mac, MAC_ADDR_LEN);
    ethHeader->ethertype = htons(0x0800); // IPv4

    // IP header
    IPHeader* ipHeader = reinterpret_cast<IPHeader*>(packetPtr + ETHERNET_HEADER_LEN);
    ipHeader->ver_ihl = (4 << 4) | (IP_HDR_LEN / sizeof(unsigned int));
    ipHeader->tos = 0;
    ipHeader->total_len = htons(IP_HDR_LEN + sizeof(UDPHeader) + data.size());
    ipHeader->identification = htons(1);
    ipHeader->flags_offset = htons(0);
    ipHeader->ttl = 128;
    ipHeader->protocol = 17; // UDP protocol
    ipHeader->checksum = 0;

    struct in_addr srcAddr, destAddr;
    inet_pton(AF_INET, this->SrcIpAddress.c_str(), &srcAddr);
    inet_pton(AF_INET, this->ipAddress.c_str(), &destAddr);

    ipHeader->src_ip = srcAddr.s_addr;
    ipHeader->dest_ip = destAddr.s_addr;

    // Calculate IP checksum
    ipHeader->checksum = calculateChecksum(reinterpret_cast<unsigned short*>(ipHeader), IP_HDR_LEN / 2);

    // UDP header
    UDPHeader* udpHeader = reinterpret_cast<UDPHeader*>(packetPtr + ETHERNET_HEADER_LEN + IP_HDR_LEN);
    udpHeader->src_port = htons(this->srcPort);
    udpHeader->dst_port = htons(this->dstPort);
    udpHeader->length = htons(sizeof(UDPHeader) + data.size());
    udpHeader->checksum = 0;

    // Copy the data
    memcpy(packetPtr + ETHERNET_HEADER_LEN + IP_HDR_LEN + sizeof(UDPHeader), data.data(), data.size());

    // Send the packet using Npcap
    if (pcap_sendpacket(this->handle, packet.data(), packet.size()) != 0) {
        std::cerr << "Error sending UDP packet: " << pcap_geterr(this->handle) << std::endl;
        return false;
    }

    return true;

}

std::vector<uint8_t> UDPConnection::receiveData()
{
    std::vector<uint8_t> data;
    struct pcap_pkthdr* header;
    const unsigned char* recvPacket;
    int res;

    while ((res = pcap_next_ex(handle, &header, &recvPacket)) >= 0) {
        if (res == 0) {
            continue; // Timeout elapsed
        }

        IPHeader* ipHeader = (IPHeader*)(recvPacket + ETHERNET_HEADER_LEN);
        UDPHeader* udpHeader = (UDPHeader*)(recvPacket + ETHERNET_HEADER_LEN + IP_HDR_LEN);

        if (ntohs(udpHeader->dst_port) == srcPort) {
            unsigned char* payload = (unsigned char*)(recvPacket + ETHERNET_HEADER_LEN + IP_HDR_LEN + sizeof(UDPHeader));
            size_t payloadSize = ntohs(udpHeader->length) - sizeof(UDPHeader);
            data.assign(payload, payload + payloadSize);
            break;
        }
    }

    if (res < 0) {
        std::cerr << "Error receiving packet: " << pcap_geterr(handle) << std::endl;
    }

    return data;
}

// Calculate checksum
unsigned short UDPConnection::calculateChecksum(unsigned short* buffer, size_t size) {
    unsigned long sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum += buffer[i];
        if (sum & 0xFFFF0000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    return static_cast<unsigned short>(~sum);
}
