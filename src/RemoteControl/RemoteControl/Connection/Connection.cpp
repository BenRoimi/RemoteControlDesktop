#include "Connection.h"
#include <iphlpapi.h>

bool Connection::configureSocket()
{
    pcap_if_t* d;

    // Get the list of available devices
    if (pcap_findalldevs(&this->alldevs, this->errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << this->errbuf << std::endl;
        return false;
    }

    // Display available interfaces
    int i = 0;
    for (d = this->alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        std::cout << std::endl;
    }

    if (i == 0) {
        std::cerr << "No interfaces found! Make sure Npcap is installed." << std::endl;
        pcap_freealldevs(this->alldevs);
        return false;
    }

    // Let user select an interface, can be chnaged to automatic in the continuation
    int choice;
    std::cout << "Select an interface (1-" << i << "): ";
    std::cin >> choice;

    if (choice < 1 || choice > i) {
        std::cerr << "Invalid selection." << std::endl;
        pcap_freealldevs(this->alldevs);
        return false;
    }

    // Traverse the list again to get the selected device
    d = this->alldevs;
    for (int j = 1; j < choice; ++j) {
        d = d->next;
    }
    this->selected_device = d->name;
    std::cout << "Selected interface: " << this->selected_device << std::endl;

    // Retrieve the IP address of the selected device
    for (pcap_addr_t* addr = d->addresses; addr != nullptr; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) { // Check if the address is IPv4
            sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(addr->addr);
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip));
            this->SrcIpAddress = ip;

            std::cout << "IP Address of selected interface: " << this->SrcIpAddress << std::endl;
            break;
        }
    }

    if (this->SrcIpAddress.empty()) {
        std::cerr << "No IPv4 address found for the selected interface." << std::endl;
        pcap_freealldevs(this->alldevs);
        return false;
    }

    // Open the selected device
    handle = pcap_open_live(this->selected_device, 65536, 1, 1000, this->errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << this->selected_device << " - " << this->errbuf << std::endl;
        pcap_freealldevs(this->alldevs);
        return false;
    }

    // Get local mac address
    if (!GetLocalMacAddress(src_mac)) {
        fprintf(stderr, "Failed to get local MAC address\n");
        return false;
    }
}

bool Connection::configureSocket(Connection* other)
{
    if (!other) {
        std::cerr << "Error: Other connection is null." << std::endl;
        return false;
    }

    // Copy essential attributes
    srcPort = other->srcPort;
    dstPort = other->dstPort;
    DstIpAddress = other->DstIpAddress;
    SrcIpAddress = other->SrcIpAddress;
    std::copy(std::begin(other->src_mac), std::end(other->src_mac), std::begin(src_mac));
    std::copy(std::begin(other->dest_mac), std::end(other->dest_mac), std::begin(dest_mac));

    // Copy Npcap-specific settings
    alldevs = other->alldevs;
    selected_device = other->selected_device;

    // Open the selected device: best practice is to recreate handle
    handle = pcap_open_live(this->selected_device, 65536, 1, 1000, this->errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << this->selected_device << " - " << this->errbuf << std::endl;
        pcap_freealldevs(this->alldevs);
        return false;
    }

    return true;
}

void Connection::GetMacAddress(unsigned char* mac, in_addr destip)
{
    unsigned char local_mac[MAC_ADDR_LEN];
    if (!GetLocalMacAddress(local_mac)) {
        std::cerr << "Failed to get local MAC address" << std::endl;
        pcap_close(this->handle);
        pcap_freealldevs(this->alldevs);
        return;
    }

    if (foundDestMac) {
        return;
    }

    EthernetHeader ethHeader = { 0 };
    ArpHeader arpHeader = { 0 };

    // ****************** Ethernet Header ******************
    memset(ethHeader.dest_mac, 0xFF, MAC_ADDR_LEN); // Destination MAC (broadcast)
    memcpy(ethHeader.src_mac, local_mac, MAC_ADDR_LEN); // Source MAC
    ethHeader.ethertype = htons(0x0806); // Ethertype (ARP)

    // ****************** ARP Header ******************
    arpHeader.hwType = htons(0x0001); // Hardware type (Ethernet)
    arpHeader.protocolType = htons(0x0800); // Protocol type (IPv4)
    arpHeader.hwSize = MAC_ADDR_LEN; // Hardware size (MAC length)
    arpHeader.protocolSize = IPV4_ADDR_LEN; // Protocol size (IPv4 length)
    arpHeader.opcode = htons(0x0001); // Opcode (ARP Request)

    // Sender MAC and IP
    memcpy(arpHeader.senderMAC, local_mac, MAC_ADDR_LEN); // Sender MAC address
    struct sockaddr_in local_addr;
    inet_pton(AF_INET, this->SrcIpAddress.c_str(), &(local_addr.sin_addr)); // Use your local IP here
    memcpy(arpHeader.senderIP, &local_addr.sin_addr, IPV4_ADDR_LEN); // Sender IP address

    // Target MAC and IP
    memset(arpHeader.targetMAC, 0x00, MAC_ADDR_LEN); // Target MAC address (unknown)
    memcpy(arpHeader.targetIP, &destip, IPV4_ADDR_LEN); // Target IP address

    // Create the packet by combining Ethernet and ARP headers
    unsigned char packet[ARP_PACKET_LEN];
    memcpy(packet, &ethHeader, sizeof(EthernetHeader));
    memcpy(packet + sizeof(EthernetHeader), &arpHeader, sizeof(ArpHeader));

    //// Send the ARP request
    //if (pcap_sendpacket(handle, packet, ARP_PACKET_LEN) != 0) {
    //    std::cerr << "Error sending ARP request: " << pcap_geterr(handle) << std::endl;
    //    pcap_close(handle);
    //    pcap_freealldevs(alldevs);
    //    return;
    //}
    //// Listen for the ARP reply
    //struct pcap_pkthdr* header;
    //const unsigned char* recvPacket;
    //while (pcap_next_ex(handle, &header, &recvPacket) >= 0) {
    //    if (recvPacket[12] == 0x08 && recvPacket[13] == 0x06 && recvPacket[20] == 0x00 && recvPacket[21] == 0x02) { // ARP reply
    //        if (memcmp(recvPacket + 28, &destip, IPV4_ADDR_LEN) == 0) {
    //            memcpy(mac, recvPacket + 22, MAC_ADDR_LEN);
    //            break;
    //        }
    //    }
    //}

    const int retries = 3; // Maximum retries
    const int timeout_sec = 2; // Timeout in seconds
    bool macFound = false;

    for (int attempt = 0; !macFound; ++attempt) {
        if (attempt >= retries) {
            std::cerr << "Can't find the desired arp, exiting" << std::endl;
            exit(1);
        }
        // Send the ARP request
        if (pcap_sendpacket(handle, packet, ARP_PACKET_LEN) != 0) {
            std::cerr << "Error sending ARP request: " << pcap_geterr(handle) << std::endl;
            continue;
        }

        std::cout << "Sent ARP request, attempt " << (attempt + 1) << std::endl;

        // Wait for the ARP reply
        struct pcap_pkthdr* header;
        const unsigned char* recvPacket;
        int result;

        time_t start = time(nullptr);
        while ((result = pcap_next_ex(handle, &header, &recvPacket)) >= 0) {
            if (time(nullptr) - start > timeout_sec) {
                std::cerr << "Timeout waiting for ARP reply" << std::endl;
                break;
            }

            if (recvPacket[12] == 0x08 && recvPacket[13] == 0x06 && recvPacket[20] == 0x00 && recvPacket[21] == 0x02) { // ARP reply
                if (memcmp(recvPacket + 28, &destip, IPV4_ADDR_LEN) == 0) {
                    memcpy(mac, recvPacket + 22, MAC_ADDR_LEN);
                    macFound = true;
                    foundDestMac = true;
                    break;
                }
            }
        }
    }

    std::cout << "MAC Address: ";
    for (int i = 0; i < MAC_ADDR_LEN; ++i) {
        printf("%02X", mac[i]);
        if (i != MAC_ADDR_LEN - 1) std::cout << ":";
    }
    std::cout << std::endl;
}

bool Connection::GetLocalMacAddress(unsigned char* mac)
{
    if (selected_device == nullptr) {
        std::cerr << "No selected device for retrieving MAC address." << std::endl;
        return false;
    }

    PIP_ADAPTER_INFO AdapterInfo = nullptr;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    // Allocate memory for adapter info
    AdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    if (AdapterInfo == nullptr) {
        return false; // Memory allocation failed
    }

    // Check if buffer is sufficient, and reallocate if necessary
    if (GetAdaptersInfo(AdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(AdapterInfo);
        AdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (AdapterInfo == nullptr) {
            return false; // Memory allocation failed
        }
    }

    // Retrieve adapter information
    if (GetAdaptersInfo(AdapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;

        // Iterate through adapters to match the selected device
        while (pAdapterInfo) {
            // Check if the selected device matches the adapter's name
            if (strstr(selected_device, pAdapterInfo->AdapterName) != nullptr) {
                memcpy(mac, pAdapterInfo->Address, MAC_ADDR_LEN);
                free(AdapterInfo);
                return true;
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    free(AdapterInfo);
    std::cerr << "Failed to find the MAC address for the selected device." << std::endl;
    return false;
}

std::array<unsigned char, MAC_ADDR_LEN> Connection::getDestMac() const
{
    std::array<unsigned char, MAC_ADDR_LEN> mac;
    std::copy(std::begin(dest_mac), std::end(dest_mac), mac.begin());

    return mac;
}
