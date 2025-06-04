#include "TCPConnection.h"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <map>
#include <algorithm>
#include <chrono>
#include <random>

#pragma comment(lib, "ws2_32.lib")  // Link with ws2_32.lib for Winsock functions
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")

TCPConnection::TCPConnection()
{
}

TCPConnection::TCPConnection(int srcPort, int dstPort, unsigned short mss_value)
{
    /*
     * Initializes TCPConnection with source/destination ports and MSS.
     * Input:
     *   - srcPort: local TCP port
     *   - dstPort: remote TCP port
     *   - mss_value: Maximum Segment Size to use for sending
     */

    this->srcPort = srcPort;
    this->dstPort = dstPort;
    this->isConnected = true;
    this->most_updated_seq = generateISN();
    this->mss = mss_value;
    this->window_size = 65535;
    configureSocket();
}

TCPConnection::TCPConnection(int srcPort, int dstPort, unsigned short mss_value, Connection* other)
{
    /*
      * Initializes TCPConnection with an existing socket base (Connection*)
    */
    this->srcPort = srcPort;
    this->dstPort = dstPort;
    this->isConnected = true;
    this->most_updated_seq = generateISN();
    this->mss = mss_value;
    this->window_size = 65535;
    configureSocket(other);
}

TCPConnection::~TCPConnection()
{
    pcap_close(this->handle);
    pcap_freealldevs(alldevs);
}

bool TCPConnection::initializeConnection(const std::string& ipAddress)
{
    /*
     * Starts a client-side connection to a server.
     * Input: remote IP address
     * Output: true if connection was successful, false otherwise
     */

    this->DstIpAddress = ipAddress;

    // Get mac adrress
    if (ipAddress == "127.0.0.1") {
        GetLocalMacAddress(dest_mac);
    }
    else {
        char ip_Address[16];
        if (this->DstIpAddress.size() < sizeof(ip_Address)) {
            std::copy(this->DstIpAddress.begin(), this->DstIpAddress.end(), ip_Address);
            ip_Address[this->DstIpAddress.size()] = '\0'; // Null-terminate the C-string
        }

        in_addr destip;
        if (inet_pton(AF_INET, ip_Address, &destip) != 1) {
            std::cerr << "Invalid IP address format." << std::endl;
            return false;
        }

        GetMacAddress(dest_mac, destip);

        if (!foundDestMac) {
            return false;
        }

    }

    if (!openDevice()) return false;

    // Send Syn
    sendTCPControlSegment(0, this->most_updated_seq, TCP_FLAG_SYN, true);

    // Wait for SYN-ACK
    uint32_t dst_ip, src_ip;
    inet_pton(AF_INET, this->DstIpAddress.c_str(), &dst_ip);
    inet_pton(AF_INET, this->SrcIpAddress.c_str(), &src_ip);
    uint32_t seq_num, ack_num;
    if (!waitForSYNACK(
        dst_ip, // Expected source IP (destination IP in the sent packet)
        src_ip, // Expected destination IP (source IP in the sent packet)
        this->dstPort,              // Expected source port
        this->srcPort,              // Expected destination port
        TCP_FLAG_ACK | TCP_FLAG_SYN,                       // Expected flags (SYN-ACK)
        seq_num, ack_num)) {
        return false;
    }

    // Send ACK
    this->most_updated_received_ack = ack_num;
    this->most_updated_seq += 1;
    sendTCPControlSegment(this->most_updated_seq, ack_num, TCP_FLAG_ACK, false);
    most_updated_remote_seq = ack_num;
    
    return true;
}

bool TCPConnection::WaitForConnection()
{
    /*
     * Waits for an incoming TCP SYN packet (server-side).
     * Performs the server side of the 3-way handshake.
     * Output: true on success, false on error
     */

    // Allocate memory for the packet
    unsigned char packet[ETHERNET_HEADER_LEN + IP_HDR_LEN + TCP_HDR_LEN];

    // Set up the packet capture filter for TCP packets (SYN flag)
    struct pcap_pkthdr* header;
    const unsigned char* packet_data;

    while (true) {
        // Capture a packet
        int res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) {
            // Timeout, continue capturing
            continue;
        }
        if (res == -1) {
            std::cerr << "Error capturing packet: " << pcap_geterr(handle) << std::endl;
            return false;
        }

        // Ethernet header
        EthernetHeader* eth_hdr = (EthernetHeader*)packet_data;

        // Check if the packet is an IPv4 packet (Ethernet Type 0x0800)
        if (ntohs(eth_hdr->ethertype) != 0x0800) {
            continue; // Not an IPv4 packet
        }

        // IP header
        IPHeader* ip_hdr = (IPHeader*)(packet_data + ETHERNET_HEADER_LEN);

        // Check if it's a TCP packet (Protocol 6)
        if (ip_hdr->protocol != IPPROTO_TCP) {
            continue;
        }

        // TCP header
        TCPHeader* tcp_hdr = (TCPHeader*)(packet_data + ETHERNET_HEADER_LEN + IP_HDR_LEN);

        if (ntohs(tcp_hdr->dest_port) != this->srcPort) {
            continue; // Not for this service
        }

        // Check if the packet has the SYN flag set
        if (tcp_hdr->flags == TCP_FLAG_SYN) {  // SYN flag is set (0x02)
            std::cout << "Received SYN packet. Sending SYN-ACK..." << std::endl;
            this->DstIpAddress = convertIpToString(ip_hdr->src_ip);
            memcpy(this->dest_mac, eth_hdr->src_mac, MAC_ADDR_LEN);

            unsigned short receivedMss = this->CheckMSS(packet_data);

            if (receivedMss < this->mss) {
                this->mss = receivedMss; // settle on the smallest mss
            }

            sendTCPControlSegment(ntohl(tcp_hdr->seq_num) + 1, this->most_updated_seq, TCP_FLAG_SYN | TCP_FLAG_ACK, true);

            // Wait for ACK
            while (true) {
                int ack_res = pcap_next_ex(handle, &header, &packet_data);
                if (ack_res == 0) {
                    continue; // Timeout, keep waiting
                }
                if (ack_res == -1) {
                    std::cerr << "Error capturing packet: " << pcap_geterr(handle) << std::endl;
                    return false;
                }

                EthernetHeader* ack_eth_hdr = (EthernetHeader*)packet_data;
                if (ntohs(ack_eth_hdr->ethertype) != 0x0800) {
                    continue;
                }

                IPHeader* ack_ip_hdr = (IPHeader*)(packet_data + ETHERNET_HEADER_LEN);
                if (ack_ip_hdr->protocol != IPPROTO_TCP) {
                    continue;
                }

                TCPHeader* ack_tcp_hdr = (TCPHeader*)(packet_data + ETHERNET_HEADER_LEN + IP_HDR_LEN);
                if (ack_tcp_hdr->flags == 0x10 && ntohs(ack_tcp_hdr->dest_port) == this->srcPort) { // ACK flag
                    most_updated_seq = ntohl(ack_tcp_hdr->seq_num);
                    most_updated_remote_seq = ntohl(ack_tcp_hdr->ack_num);
                    std::cout << "Received ACK packet. Handshake complete!" << std::endl;
                    return true;
                }
            }
        }
    }
}

void TCPConnection::closeConnection()
{
    /*
     * Initiates connection termination using FIN/ACK exchange.
     */
    isConnected = false;
    queueCondition.notify_all();
    std::cout << "Initiating connection termination..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    // Send FIN
    if (!sendTCPControlSegment(most_updated_remote_seq + 1, most_updated_seq, TCP_FLAG_FIN, false)) {
        std::cerr << "Failed to send final FIN." << std::endl;
    }
    else {
        std::cout << "FIN sent." << std::endl;
    }
    most_updated_seq++; // Increment sequence number for FIN

    // Wait for ACK of FIN
    if (!waitForSpecificACK(most_updated_seq, std::chrono::milliseconds(10000))) {
        std::cerr << "Timeout waiting for ACK of FIN." << std::endl;
        return;
    }
    std::cout << "ACK for FIN received." << std::endl;

    // Wait for FIN from peer
    TCPHeader incomingHeader{};
    std::vector<u_char> incomingPacket;
    while (true) {
        if (!receivePacket(incomingPacket) || !parseTCPHeader(incomingPacket, incomingHeader)) {
            std::cerr << "Error receiving or parsing FIN from peer." << std::endl;
            return;
        }
        if (incomingHeader.flags & TCP_FLAG_FIN) {
            std::cout << "FIN from peer received." << std::endl;
            most_updated_remote_seq = incomingHeader.seq_num;
            break;
        }
    }

    // Send final ACK
    if (!sendTCPControlSegment(most_updated_remote_seq, most_updated_seq, TCP_FLAG_ACK, false)) {
        std::cerr << "Failed to send final ACK." << std::endl;
    }
    else {
        std::cout << "Final ACK sent. Connection terminated." << std::endl;
    }
}

void TCPConnection::segmentPayloadSeperator(const std::vector<u_char>& payload_data, std::queue<TCPSegment>& segments)
{
    /*
    * Splits raw payload data into MSS-sized TCPSegments.
    * Input:
    *   - payload_data: full data buffer to be sent
    * Output:
    *   - segments: output queue with individual segments
    */

    int payload_len = payload_data.size();
    unsigned int startSequence = most_updated_seq;
    for (int offset = 0; offset < payload_len; offset += this->mss) {
        // Determine the size of the current segment
        int segment_len = (this->mss < (payload_len - offset)) ? this->mss : (payload_len - offset);

        // Extract the segment data from the payload
        std::vector<u_char> segment_data(payload_data.begin() + offset, payload_data.begin() + offset + segment_len);

        // Create a new segment
        TCPSegment segment;
        segment.seq_num = startSequence + offset;

        // Assign the segment data (already a vector<u_char>)
        segment.data = segment_data;

        segment.checksum = calculateChecksum(segment.data);

        // Append the segment to the vector
        segments.push(segment);
    }
}

std::vector<u_char> TCPConnection::reconstructPayload(std::vector<TCPSegment>& orderedSegments, unsigned int& expectedSeqNum) {
    /*
     * Reassembles ordered TCP segments into a single payload vector.
     * Inputs:
     *   - orderedSegments: vector of in-order segments
     *   - expectedSeqNum: starting sequence number
     * Output:
     *   - byte stream of full payload
     */

    std::vector<u_char> payload;

    // Iterate over the ordered segments and append them if they match the expected sequence number
    for (auto& segment : orderedSegments) {
        if (segment.seq_num == expectedSeqNum) {
            // Append the segment's data to the payload
            payload.insert(payload.end(), segment.data.begin(), segment.data.end());
            expectedSeqNum += segment.data.size();
        }
        else if (segment.seq_num > expectedSeqNum) {
            break; // Out-of-order segment; stop processing
        }
    }

    // Remove acknowledged segments from the list
    orderedSegments.erase(
        std::remove_if(orderedSegments.begin(), orderedSegments.end(),
            [&](const TCPSegment& s) { return s.seq_num < expectedSeqNum; }),
        orderedSegments.end());

    return payload;
}


bool TCPConnection::sendSegment(const std::vector<u_char>& rawSegment) {
    /*
     * Sends a raw TCP segment through the pcap device.
     * Input: raw packet data
     * Output: true on success
     */

    if (pcap_sendpacket(this->handle, rawSegment.data(), rawSegment.size()) != 0) {
        std::cerr << "Error sending segment: " << pcap_geterr(this->handle) << std::endl;
        return false;
    }
    return true;
}

bool TCPConnection::parseTCPHeader(const std::vector<u_char>& rawPacket, TCPHeader& header) {
    /*
     * Alternate function to parse TCP header from full raw packet.
     */

    if (rawPacket.size() < sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader)) {
        std::cerr << "Packet too small to contain a TCP header." << std::endl;
        return false;
    }

    const TCPHeader* tcpHeader = reinterpret_cast<const TCPHeader*>(rawPacket.data() + sizeof(EthernetHeader) + sizeof(IPHeader));
    header = *tcpHeader;

    // Convert fields from network to host byte order
    header.src_port = ntohs(header.src_port);
    header.dest_port = ntohs(header.dest_port);
    header.seq_num = ntohl(header.seq_num);
    header.ack_num = ntohl(header.ack_num);
    return true;
}


bool TCPConnection::waitForACKs(std::vector<TCPSegment>& segments, const std::chrono::milliseconds& timeout) {
    /*
     * Waits for all segments in a vector to be acknowledged.
     * Inputs:
     *   - segments: segments to monitor
     *   - timeout: timeout per segment
     * Output: true if all acknowledged; false on timeout
     */

    for (auto& segment : segments) {
        int retransmissionAttempts = 0; // Initialize retransmission counter for each segment

        while (!segment.acknowledged) {
            auto now = std::chrono::steady_clock::now();

            // Check if the segment has timed out
            if (segment.sent_time + timeout <= now) {
                if (retransmissionAttempts >= 3) {
                    std::cerr << "Max retransmission attempts reached for sequence number: "
                        << segment.seq_num + segment.data.size() << ". Closing program..." << std::endl;
                    return false; // Exit the program due to failed retransmissions
                }

                std::cerr << "Timeout waiting for ACK for sequence number: "
                    << segment.seq_num + segment.data.size() << ". Retransmitting..." << std::endl;

                // Retransmit the segment
                std::vector<u_char> rawSegment;
                if (!createSegment(segment, rawSegment) || !sendSegment(rawSegment)) {
                    std::cerr << "Failed to retransmit segment with sequence number: "
                        << segment.seq_num + segment.data.size() << std::endl;
                    return false;
                }

                // Update the send time after retransmission
                segment.sent_time = std::chrono::steady_clock::now();
                ++retransmissionAttempts; // Increment retransmission counter
            }

            // Check for incoming ACKs (the receive thread listens for acks)
            if (most_updated_received_ack == segment.seq_num + segment.data.size()) {
                std::cout << "ACK received for sequence number: " << segment.seq_num << std::endl;
                segment.acknowledged = true;
                break;
            }
        }
    }
    return true;
}


std::vector<u_char> TCPConnection::serializeHeadersAndPayload(const EthernetHeader& ethHeader, const IPHeader& ipHeader, const TCPHeader& tcpHeader, const std::vector<u_char>& payload, const std::vector<u_char>& tcpOptions) {
    /*
     * Serializes Ethernet, IP, and TCP headers with optional payload and options.
     * Output: raw byte vector
     */

    std::vector<u_char> rawSegment;

    // Serialize Ethernet, IP, and TCP headers
    rawSegment.insert(rawSegment.end(), reinterpret_cast<const u_char*>(&ethHeader), reinterpret_cast<const u_char*>(&ethHeader) + sizeof(EthernetHeader));
    rawSegment.insert(rawSegment.end(), reinterpret_cast<const u_char*>(&ipHeader), reinterpret_cast<const u_char*>(&ipHeader) + sizeof(IPHeader));
    rawSegment.insert(rawSegment.end(), reinterpret_cast<const u_char*>(&tcpHeader), reinterpret_cast<const u_char*>(&tcpHeader) + sizeof(TCPHeader));

    // Append TCP options if present
    if (!tcpOptions.empty()) {
        rawSegment.insert(rawSegment.end(), tcpOptions.begin(), tcpOptions.end());
    }

    // Append the payload
    rawSegment.insert(rawSegment.end(), payload.begin(), payload.end());

    return rawSegment;
}

void TCPConnection::sendAckUpdateThreadFunc()
{
    /*
     * Sends updated ACKs to the peer if new data was received.
     * Threaded function.
     */

    unsigned int lastSentAck = most_updated_remote_seq;
    while (isConnected) {
        if (most_updated_remote_seq != lastSentAck) {
            sendTCPControlSegment(most_updated_remote_seq, most_updated_seq, TCP_FLAG_ACK, false);
            lastSentAck = most_updated_remote_seq;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

void TCPConnection::processSegments(std::vector<TCPSegment>& receivedSegments, std::vector<u_char>& reconstructedPayload){
    /*
     * Reorders, acknowledges, and reassembles segments into complete payloads.
     * Inputs:
     *   - receivedSegments: list of unordered segments
     *   - reconstructedPayload: output payload built from ordered segments
     */

    std::map<uint32_t, TCPSegment> outOfOrderBuffer;
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    while (this->isConnected) {
        TCPSegment segment;

        // Wait for a new segment to be added to the queue
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCondition.wait(lock, [this] { return (!segmentQueue.empty() || !isConnected); });

            if (!isConnected && segmentQueue.empty()) {
                break;
            }

            // Retrieve and remove the segment from the queue
            segment = std::move(segmentQueue.front());
            segmentQueue.pop();
        }

        if (this->most_updated_remote_seq == segment.seq_num) {
            this->most_updated_remote_seq = segment.seq_num + segment.data.size();
            std::this_thread::sleep_for(std::chrono::milliseconds(200)); // sleep for letting the ack get sent

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                for (u_char dataByte : segment.data) {
                    this->receivedDataStreamQueue.push(dataByte);
                }
            }

            // Clear processed data
            receivedSegments.clear();

            while (!outOfOrderBuffer.empty()) {
                auto it = outOfOrderBuffer.begin();
                if (it->first == this->most_updated_remote_seq) {
                    TCPSegment nextSegment = std::move(it->second);
                    outOfOrderBuffer.erase(it);

                    this->most_updated_remote_seq += nextSegment.data.size();
                    // or this->most_updated_remote_seq = nextSegment.seq_num; same thing
                    {
                        std::lock_guard<std::mutex> lock(queueMutex);
                        for (u_char dataByte : nextSegment.data) {
                            this->receivedDataStreamQueue.push(dataByte);
                        }
                    }
                }
                else {
                    break;
                }
            }
        }
        else if (this->most_updated_remote_seq + segment.data.size() < segment.seq_num) {
            // some segment is missing
            outOfOrderBuffer[segment.seq_num] = std::move(segment);
        }

    }
}

void TCPConnection::senderThreadFunc()
{
    /*
     * Continuously sends segments from segmentsToSendQueue.
     * Threaded function.
     */
    while (!stopSendingFlag) {
        if (!segmentsToSendQueue.empty()) {
            TCPSegment segmentToSend;
            segmentToSend = segmentsToSendQueue.front();

            // Create and send each TCP segment
            std::vector<u_char> rawSegment;
            if (!createSegment(segmentToSend, rawSegment)) {
                std::cerr << "Failed to create segment for sequence number: " << segmentToSend.seq_num << std::endl;
                return;
            }

            if (!sendSegment(rawSegment)) {
                std::cerr << "Failed to send segment with sequence number: " << segmentToSend.seq_num << std::endl;
                return;
            }

            segmentToSend.acknowledged = false;
            segmentToSend.sent_time = std::chrono::steady_clock::now();

            {
                std::unique_lock<std::mutex> lock(SentQueueMutex);
                SentSegmentsQueue.push(segmentToSend);
            }

            {
                std::unique_lock<std::mutex> lock(sendQueueMutex);
                segmentsToSendQueue.pop();
            }
            if (most_updated_seq < segmentToSend.seq_num + segmentToSend.data.size()) { // Check, maybe it's retransmission
                most_updated_seq = segmentToSend.seq_num + segmentToSend.data.size();
            }
        }
    }
}

void TCPConnection::CheckRetransmissionThreadFunc()
{
    /*
     * Periodically checks sent segments for ACKs.
     * Retransmits if timeout expires.
     * Threaded function.
     */

    while (!stopSendingFlag) {
        // Check the ack and remove segments that received ack from sentQueue
        if (!SentSegmentsQueue.empty()) {
            if (most_updated_received_ack >= SentSegmentsQueue.front().seq_num + SentSegmentsQueue.front().data.size()) {
                {
                    {
                        std::unique_lock<std::mutex> lock(SentQueueMutex);
                        SentSegmentsQueue.pop();
                    }
                }
            }
            else {
                // Check if timer has expiered, retranssmit make the timer of others bigger 
                if (SentSegmentsQueue.front().sent_time + std::chrono::milliseconds(ACK_WAIT_TIME) <= std::chrono::steady_clock::now()) {
                    // Retransmitt

                    TCPSegment sendSegment = SentSegmentsQueue.front();
                    {
                        std::unique_lock<std::mutex> lock(SentQueueMutex);
                        SentSegmentsQueue.pop();
                    }
                    {
                        std::unique_lock<std::mutex> lock(sendQueueMutex);
                        segmentsToSendQueue.push(sendSegment);
                    }

                    // Timer of others bigger 
                    {
                        std::lock_guard<std::mutex> lock(SentQueueMutex);

                        std::queue<TCPSegment> tempQueue; // Temporary queue to hold updated segments

                        while (!SentSegmentsQueue.empty()) {
                            TCPSegment segment = SentSegmentsQueue.front();
                            SentSegmentsQueue.pop();

                            // Update the sent_time to now
                            segment.sent_time = std::chrono::steady_clock::now();

                            // Push the updated segment to the temporary queue
                            tempQueue.push(segment);
                        }

                        // Move the temporary queue back to the original queue
                        SentSegmentsQueue = std::move(tempQueue);
                    }
                }
            }
        }
        
    }
}

size_t TCPConnection::calculateBufferSent()
{
    /*
     * Computes the total size of unsent + unacknowledged buffers.
     */

    size_t totalSize = 0;

    // Lock and calculate the size of the segments in the "segmentsToSendQueue"
    {
        std::lock_guard<std::mutex> lock(sendQueueMutex);
        std::queue<TCPSegment> tempQueue = segmentsToSendQueue; // Copy the queue to avoid modifying it
        while (!tempQueue.empty()) {
            totalSize += tempQueue.front().data.size();
            tempQueue.pop();
        }
    }

    // Lock and calculate the size of the segments in the "SentSegmentsQueue"
    {
        std::lock_guard<std::mutex> lock(SentQueueMutex);
        std::queue<TCPSegment> tempQueue = SentSegmentsQueue; // Copy the queue to avoid modifying it
        while (!tempQueue.empty()) {
            totalSize += tempQueue.front().data.size();
            tempQueue.pop();
        }
    }

    return totalSize;
}

bool TCPConnection::createSegment(const TCPSegment& segment, std::vector<u_char>& rawSegment) {
    /*
     * Creates a raw TCP/IP packet from a TCPSegment.
     * Output: raw byte vector
     */

    // Create the IP header
    IPHeader ipHeader;
    createIPHeader(ipHeader,
        this->SrcIpAddress,
        this->DstIpAddress,
        64,                // Default TTL
        IPPROTO_TCP,       // Protocol type (TCP)
        0,                 // Flags/offset
        sizeof(IPHeader) + sizeof(TCPHeader) + segment.data.size()); // Total length

    // Create the TCP header
    TCPHeader tcpHeader;
    createTCPHeader(tcpHeader,
        this->srcPort,            // Default source port
        this->dstPort,               // Default destination port
        segment.seq_num,  // Sequence number
        this->most_updated_remote_seq,                // Acknowledgment number 
        0x18,             // Default flags (PSH + ACK for data transmission)
        65535, 0, segment.checksum);           // Default window size

    EthernetHeader eth_hdr;
    createEthernetHeader(eth_hdr, this->src_mac, this->dest_mac, 0x0800);

    // Serialize the headers and append the payload
    rawSegment = serializeHeadersAndPayload(eth_hdr, ipHeader, tcpHeader, segment.data, {});

    return true;
}


bool TCPConnection::sendData(const std::vector<uint8_t>& data)
{
    /*
     * Segments and sends a data vector over TCP.
     * Input: vector of bytes to send
     * Output: true if all segments were ACKed
     */

    stopSendingFlag = false;
    unsigned int seqInStart = most_updated_seq;
    std::queue<TCPSegment> segments;

    segmentPayloadSeperator(data, segments);

    // Open thread for sending segments from shared resource
    std::thread senderThread(&TCPConnection::senderThreadFunc, this);

    std::thread CheckRetransmissionThread(&TCPConnection::CheckRetransmissionThreadFunc, this);

    while (isConnected) {
        if (!segments.empty()) { 
            if (this->calculateBufferSent() + segments.front().data.size() <= this->window_size) {
                {
                    std::unique_lock<std::mutex> lock(sendQueueMutex);
                    segmentsToSendQueue.push(segments.front());
                    segments.pop();
                }
            }
        }
        else if (most_updated_received_ack == seqInStart + data.size()) {
            std::cout << "ack received, continue inputing" << std::endl;
            stopSendingFlag = true;
            break;
        }
    }

    stopSendingFlag = true;
    senderThread.join();
    CheckRetransmissionThread.join();

    return true;
}

bool TCPConnection::isPacketFromSource(const u_char* packet) {
    /*
    * Validates whether the packet originated from expected source IP and port.
    */

    // Ensure the packet has enough data for Ethernet + IP + TCP headers
    if (size_t(packet) < sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader)) {
        return false;
    }

    // Ethernet header
    EthernetHeader* eth_hdr = (EthernetHeader*)packet;

    // Check if the packet is an IPv4 packet (Ethernet Type 0x0800)
    if (ntohs(eth_hdr->ethertype) != 0x0800) {
        return false; // Not an IPv4 packet
    }

    // IP header
    IPHeader* ip_hdr = (IPHeader*)(size_t(packet) + ETHERNET_HEADER_LEN);

    // Check if it's a TCP packet (Protocol 6)
    if (ip_hdr->protocol != IPPROTO_TCP) {
        return false;
    }

    // Check source IP
    if (this->SrcIpAddress != convertIpToString(ip_hdr->dest_ip)) {
        return false;
    }

    // TCP header
    TCPHeader* tcp_hdr = (TCPHeader*)(size_t(packet) + ETHERNET_HEADER_LEN + IP_HDR_LEN);

    if (ntohs(tcp_hdr->dest_port) != this->srcPort) {
        return false; // Not for this service
    }

    return true;
}

bool TCPConnection::receivePacket(std::vector<u_char>& rawSegment) {
    /*
     * Receives a packet from the pcap device.
     * Output: fills rawPacket on success
     */

    const u_char* packet;
    struct pcap_pkthdr header;

    // Wait for the next packet
    packet = pcap_next(this->handle, &header);
    if (packet == nullptr) {
        return false; // Timeout or error
    }

    if (isPacketFromSource(packet)) {
        // Store the packet data in the rawSegment vector
        rawSegment.assign(packet, packet + header.len);
    }
    else {
        return false;
    }

    return true;
}

bool TCPConnection::parseSegment(const std::vector<u_char>& rawSegment, TCPSegment& segment) {
    /*
     * Extracts a TCPSegment from raw packet data.
     * Output: TCPSegment structure
     */

    // Extract the IP header
    const IPHeader* ipHeaderPtr = reinterpret_cast<const IPHeader*>(rawSegment.data() + sizeof(EthernetHeader));

    // Extract headers
    const TCPHeader* tcpHeader = reinterpret_cast<const TCPHeader*>(rawSegment.data() + sizeof(EthernetHeader) + sizeof(IPHeader));
    const u_char* payload = rawSegment.data() + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader);
    size_t payloadSize = ntohs(ipHeaderPtr->total_len) - (sizeof(IPHeader) + sizeof(TCPHeader));

    segment.seq_num = ntohl(tcpHeader->seq_num);
    segment.data.assign(payload, payload + payloadSize);
    segment.checksum = ntohs(tcpHeader->checksum);
    return true;
}

bool TCPConnection::extractTcpHeader(const std::vector<u_char>& rawSegment, TCPHeader& tcpHeader)
{
    /*
     * Extracts and decodes a TCP header.
     * Output: TCPHeader structure
     */

    // Calculate the minimum size required for Ethernet, IP, and TCP headers
    const size_t minSize = ETHERNET_HEADER_LEN + IP_HDR_LEN + TCP_HDR_LEN;

    // Check if the rawSegment is large enough to extract the TCP header
    if (rawSegment.size() < minSize) {
        std::cerr << "Error: rawSegment size is too small to extract TCP header." << std::endl;
        return false;
    }

    // Extract the TCP header pointer from the raw data
    const u_char* tcpHeaderPtr = rawSegment.data() + ETHERNET_HEADER_LEN + IP_HDR_LEN;

    // Safely copy the TCP header from the raw data into the `tcpHeader` struct
    std::memcpy(&tcpHeader, tcpHeaderPtr, sizeof(TCPHeader));

    // Convert fields in the TCP header from network byte order to host byte order
    tcpHeader.src_port = ntohs(tcpHeader.src_port);
    tcpHeader.dest_port = ntohs(tcpHeader.dest_port);
    tcpHeader.seq_num = ntohl(tcpHeader.seq_num);
    tcpHeader.ack_num = ntohl(tcpHeader.ack_num);
    tcpHeader.window_size = ntohs(tcpHeader.window_size);
    tcpHeader.checksum = ntohs(tcpHeader.checksum);
    tcpHeader.urgent_ptr = ntohs(tcpHeader.urgent_ptr);

    return true; // Success
}


bool TCPConnection::sendTCPControlSegment(const unsigned int ackNum, const unsigned int seqNum, const uint8_t tcpFlags, bool sendMss) {
    /*
     * Sends a control TCP segment (SYN/ACK/FIN).
     * Inputs:
     *   - ackNum, seqNum: control numbers
     *   - tcpFlags: flag bits
     *   - sendMss: if true, includes MSS option
     * Output: true on success
     */

    // TCP options
    std::vector<u_char> tcpOptions;
    if (sendMss) {
        // Add MSS option (4 bytes)
        tcpOptions.push_back(0x02);        // Kind: MSS
        tcpOptions.push_back(0x04);        // Length: 4 bytes
        uint16_t mssValue = this->mss;  // Convert to network byte order
        tcpOptions.push_back(static_cast<u_char>((mssValue >> 8) & 0xFF)); // High byte
        tcpOptions.push_back(static_cast<u_char>(mssValue & 0xFF));        // Low byte
    }

    // Create the IP header
    IPHeader ipHeader;
    createIPHeader(ipHeader,
        this->SrcIpAddress,  // Source IP address
        this->DstIpAddress,  // Destination IP address
        64,                  // Default TTL
        IPPROTO_TCP,         // Protocol type (TCP)
        0,                   // Flags/offset
        sizeof(IPHeader) + sizeof(TCPHeader) + tcpOptions.size()); // Total length (no payload)

    // Create the TCP header
    TCPHeader tcpHeader;
    createTCPHeader(tcpHeader,
        this->srcPort,         // Source port
        this->dstPort,         // Destination port
        seqNum,                // Sequence number
        ackNum,                // Acknowledgment number
        tcpFlags,              // TCP flags (e.g., ACK, FIN)
        65535,                 // Default window size
        tcpOptions.size(), 0);

    // Create the Ethernet header
    EthernetHeader eth_hdr;
    createEthernetHeader(eth_hdr, this->src_mac, this->dest_mac, 0x0800);

    // Serialize headers and payload (include TCP options if present)
    std::vector<u_char> packet = serializeHeadersAndPayload(eth_hdr, ipHeader, tcpHeader, {}, tcpOptions);


    // Send the segment
    return sendSegment(packet);
}

void TCPConnection::receiveData() {
    /*
     * Main loop that receives TCP segments, verifies, and dispatches them.
     * No input. Called in a separate thread.
     */

    std::vector<TCPSegment> receivedSegments; // Container to store received TCP segments
    std::vector<u_char> reconstructedPayload; // Reconstruct the payload from received segments

    // Launch the worker thread
    std::thread ackTimersThread(&TCPConnection::sendAckUpdateThreadFunc, this);
    std::thread workerThread(&TCPConnection::processSegments, this, std::ref(receivedSegments), std::ref(reconstructedPayload));

    while (this->isConnected) { // until connection was terminated
        // Receive raw packets from the network
        std::vector<u_char> rawPacket;
        if (!receivePacket(rawPacket)) {
            // Skip filtered segments
            continue;
        }

        // Extract TCP header
        TCPHeader header;
        if (!extractTcpHeader(rawPacket, header)) {
            std::cerr << "Error extracting TCP header." << std::endl;
            continue;
        }

        // Handle ACK packets
        if (header.flags == TCP_FLAG_ACK) {
            if (header.ack_num > this->most_updated_received_ack) {
                most_updated_received_ack = header.ack_num; // Update shared state
            }
            continue;
        }

        // Handle FIN packets
        if (header.flags == TCP_FLAG_FIN) {
            // Handle connection termination
            handleIncomingFIN();
            break;
        }

        // Parse the raw segment into a `TCPSegment`
        TCPSegment segment;
        if (!parseSegment(rawPacket, segment)) {
            std::cerr << "Error parsing a TCP segment." << std::endl;
            continue;
        }

        unsigned short checksum = calculateChecksum(segment.data);
        if (segment.checksum != checksum) {
            std::cerr << "Checksum error" << std::endl;
            continue;
        }

        // Add the segment to the queue for processing
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            segmentQueue.push(std::move(segment));
        }
        queueCondition.notify_one(); // Notify the worker thread
    }

    ackTimersThread.join();
    queueCondition.notify_all();
    workerThread.join();
    std::cout << "finish" << std::endl;
}

void TCPConnection::startReceiving()
{
    /*
     * Launches the receiving thread that handles incoming data.
     */

    receivingThread = std::thread(&TCPConnection::receiveData, this);
}

void TCPConnection::stopReceiving()
{
    /*
     * Gracefully stops the receiving thread.
     */


    isConnected = false;
    receivingThread.join();
}

bool TCPConnection::isDataEmpty()
{
    /*
     * Returns true if no data is available in the receive buffer.
     */

    if (this->receivedDataStreamQueue.empty()) {
        return true;
    }
    return false;
}

std::vector<uint8_t> TCPConnection::getData(int bytes)
{
    /*
     * Returns a specific number of bytes from the receive buffer.
     * Input: number of bytes to retrieve
     * Output: vector of retrieved bytes
     */

    std::vector<uint8_t> result;
    std::lock_guard<std::mutex> lock(queueMutex);
    int size = this->receivedDataStreamQueue.size();

    // Ensure the queue has enough data
    if (size < bytes)
    {
        std::cout << "oooooooo problem!" << std::endl;
        //throw std::runtime_error("Not enough data in the stream to satisfy request");
    }

    // Extract the requested number of bytes
    for (int i = 0; i < bytes; ++i)
    {
        result.push_back(receivedDataStreamQueue.front());
        receivedDataStreamQueue.pop();
    }

    return result;
}

std::vector<uint8_t> TCPConnection::getData()
{
    /*
     * Returns all available bytes from the receive buffer.
     */

    std::vector<uint8_t> result;
    int size = this->receivedDataStreamQueue.size();

    // Extract the requested number of bytes
    for (int i = 0; i < size; ++i)
    {
        result.push_back(receivedDataStreamQueue.front());
        receivedDataStreamQueue.pop();
    }

    return result;
}

std::string TCPConnection::getDestIp()
{
    /*
     * Returns destination ip
     * Output: destination ip
     */
    return this->DstIpAddress;
}

bool TCPConnection::getIsConnected()
{
    /*
     * Returns if there is connection
     * Output: true if there is, else if isn't
     */
    return isConnected;
}

std::string TCPConnection::getSrcIP()
{
    /*
     * Returns source ip
     * Output: source ip
     */
    return this->SrcIpAddress;
}

void TCPConnection::restartConnection()
{
    /*
     * Resets state variables to start a new connection.
     */

    this->isConnected = true;
    this->most_updated_seq = generateISN();
}

bool TCPConnection::openDevice() {
    /*
     * Opens a pcap device for capture and injection.
     */

    this->handle = pcap_open_live(selected_device, 65536, 1, 1000, errbuf);
    if (this->handle == nullptr) {
        std::cerr << "Couldn't open device: " << selected_device << " - " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return false;
    }
    return true;
}

/*
 * Function: createEthernetHeader
 * ------------------------------
 * Builds a raw Ethernet header structure for outgoing packets.
 *
 * Input:
 *   - eth_hdr: reference to the EthernetHeader struct to populate
 *   - src_mac: pointer to the source MAC address (6 bytes)
 *   - dest_mac: pointer to the destination MAC address (6 bytes)
 *   - ethertype: protocol type (e.g., 0x0800 for IPv4)
 *
 * Output:
 *   - Populates `eth_hdr` with source/destination MACs and ethertype in network byte order.
 *   - No return value (output by reference).
 *
 * Role:
 *   This function prepares the data-link layer frame header required for Ethernet transmission.
 */
void TCPConnection::createEthernetHeader(EthernetHeader& eth_hdr, const unsigned char* src_mac, const unsigned char* dest_mac, const uint16_t ethertype) const {
    memset(&eth_hdr, 0, sizeof(EthernetHeader));
    memcpy(eth_hdr.dest_mac, dest_mac, MAC_ADDR_LEN);
    memcpy(eth_hdr.src_mac, src_mac, MAC_ADDR_LEN);
    eth_hdr.ethertype = htons(ethertype);
}

/*
 * Function: createIPHeader
 * ------------------------
 * Constructs the IPv4 header for the outgoing TCP segment.
 *
 * Input:
 *   - ip_hdr: reference to the IPHeader struct to populate
 *   - src_ip: string representation of the source IPv4 address
 *   - dest_ip: string representation of the destination IPv4 address
 *   - ttl: Time-To-Live field (e.g., 64)
 *   - protocol: protocol number (e.g., 6 for TCP)
 *   - flags_offset: IP flags and fragment offset combined (typically 0)
 *   - total_len: total length of the IP packet (headers + payload)
 *
 * Output:
 *   - Fills in all IP header fields, calculates and sets the IP checksum.
 *   - No return value (modifies `ip_hdr`).
 *
 * Role:
 *   This function sets up the network layer (IP) portion of the TCP/IP packet.
 */
void TCPConnection::createIPHeader(IPHeader& ip_hdr, const std::string& src_ip, const std::string& dest_ip, const uint8_t ttl, const uint8_t protocol, const uint16_t flags_offset, const uint16_t total_len) const {
    memset(&ip_hdr, 0, sizeof(IPHeader));
    ip_hdr.ver_ihl = 0x45; // IPv4 and header length
    ip_hdr.tos = 0;
    ip_hdr.total_len = htons(total_len);
    ip_hdr.identification = 0;
    ip_hdr.flags_offset = htons(flags_offset);
    ip_hdr.ttl = ttl;
    ip_hdr.protocol = protocol;
    ip_hdr.checksum = 0;

    inet_pton(AF_INET, src_ip.c_str(), &ip_hdr.src_ip);
    inet_pton(AF_INET, dest_ip.c_str(), &ip_hdr.dest_ip);

    ip_hdr.checksum = calculateChecksum((unsigned short*)&ip_hdr, IP_HDR_LEN);
}

/*
 * Function: createTCPHeader
 * -------------------------
 * Constructs the TCP header used in the packet.
 *
 * Input:
 *   - tcp_hdr: reference to the TCPHeader struct to populate
 *   - src_port: local port
 *   - dest_port: remote port
 *   - seq_num: TCP sequence number to send
 *   - ack_num: acknowledgment number expected by peer
 *   - flags: TCP control flags (e.g., SYN, ACK, FIN)
 *   - window_size: TCP advertised window size (for flow control)
 *   - options_size: number of bytes of TCP options included
 *   - checksum: precomputed checksum value (if available; 0 if none)
 *
 * Output:
 *   - Populates the TCP header with correct network byte order values and options length.
 *
 * Role:
 *   Sets up the transport layer header with correct values for ports, sequence/ack numbers,
 *   flags, and options.
 */
void TCPConnection::createTCPHeader(TCPHeader& tcp_hdr, const uint16_t src_port, const uint16_t dest_port, const uint32_t seq_num, const uint32_t ack_num, const uint8_t flags, const uint16_t window_size, const size_t options_size, const unsigned short checksum) const {
    memset(&tcp_hdr, 0, sizeof(TCPHeader));
    tcp_hdr.src_port = htons(src_port);
    tcp_hdr.dest_port = htons(dest_port);
    tcp_hdr.seq_num = htonl(seq_num);
    tcp_hdr.ack_num = htonl(ack_num);
    size_t header_size = sizeof(TCPHeader) + options_size;
    tcp_hdr.data_offset = (header_size / 4) << 4; // Shift left to set high nibble
    tcp_hdr.flags = flags;
    tcp_hdr.window_size = htons(window_size);
    tcp_hdr.checksum = htons(checksum);
    tcp_hdr.urgent_ptr = 0;
}

/*
 * Function: createPseudoHeader
 * ----------------------------
 * Constructs a pseudo-header for TCP checksum calculation.
 * (Not sent over the wire, only used for validation.)
 *
 * Input:
 *   - psh: reference to PseudoHeader struct to populate
 *   - src_ip: source IP address as string
 *   - dest_ip: destination IP address as string
 *   - protocol: protocol number (typically 6 for TCP)
 *   - tcp_length: length of TCP header + payload
 *
 * Output:
 *   - Fills the pseudo-header used to calculate the TCP checksum.
 *   - No return value.
 *
 * Role:
 *   Required by the TCP specification to calculate a correct checksum by including portions of the IP layer.
 *   This pseudo-header is combined with the actual TCP segment when computing the checksum.
 */
void TCPConnection::createPseudoHeader(PseudoHeader& psh, const std::string& src_ip, const std::string& dest_ip, const uint8_t protocol, const uint16_t tcp_length) const {
    memset(&psh, 0, sizeof(PseudoHeader));
    inet_pton(AF_INET, src_ip.c_str(), &psh.src_addr);
    inet_pton(AF_INET, dest_ip.c_str(), &psh.dst_addr);
    psh.placeholder = 0;
    psh.protocol = protocol;
    psh.tcp_length = htons(tcp_length);
}

/*
 * Function: waitForSYNACK
 * -----------------------
 * Waits for a TCP SYN-ACK packet as part of the 3-way handshake (client-side logic).
 *
 * Purpose:
 *   This function listens for a SYN-ACK packet from a remote host in response to a previously
 *   sent SYN packet. It validates that the received packet matches the expected connection
 *   parameters (IP addresses, ports, flags). Once a valid SYN-ACK is received, it extracts
 *   the sequence and acknowledgment numbers.
 *
 * Inputs:
 *   - expected_src_ip: the source IP (of the peer) that we expect the SYN-ACK to come from (in network byte order)
 *   - expected_dest_ip: the destination IP (us) that the SYN-ACK should be addressed to (in network byte order)
 *   - expected_src_port: the port on the peer expected to send the SYN-ACK (remote server port)
 *   - expected_dest_port: our local port that the SYN-ACK should be addressed to (client port)
 *   - expected_flags: TCP flags that should be set (e.g., SYN | ACK)
 *
 * Outputs:
 *   - seq_num: (output) the sequence number of the received SYN-ACK (used to ACK back)
 *   - ack_num: (output) the acknowledgment number from the peer (should match our SYN + 1)
 *
 * Return:
 *   - true if a valid SYN-ACK is received within the timeout window
 *   - false if a timeout occurs or packet is invalid
 *
 * Role in the protocol:
 *   This function implements the second step in the TCP 3-way handshake.
 *   It is used by the client to wait for the server’s SYN-ACK and prepares the data needed to complete the connection.
 */
bool TCPConnection::waitForSYNACK(const uint32_t expected_src_ip, const uint32_t expected_dest_ip, const uint16_t expected_src_port, const uint16_t expected_dest_port, const uint8_t expected_flags, uint32_t& seq_num, uint32_t& ack_num) {
    struct pcap_pkthdr* header;
    const unsigned char* packet_data = nullptr;

    auto start_time = std::chrono::steady_clock::now();
    const std::chrono::seconds timeout_duration(5);

    while (true) {
        int res = pcap_next_ex(this->handle, &header, &packet_data);
        if (res == 1) {
            // Parse Ethernet Header
            IPHeader* ip_hdr_received = (IPHeader*)(packet_data + ETHERNET_HEADER_LEN);
            TCPHeader* tcp_hdr_received = (TCPHeader*)(packet_data + ETHERNET_HEADER_LEN + IP_HDR_LEN);

            // Check IPs and Ports
            if (*(uint32_t*)&ip_hdr_received->src_ip == expected_src_ip &&
                *(uint32_t*)&ip_hdr_received->dest_ip == expected_dest_ip &&
                tcp_hdr_received->src_port == htons(expected_src_port) &&
                tcp_hdr_received->dest_port == htons(expected_dest_port)) {

                // Check TCP Flags
                if (tcp_hdr_received->flags == expected_flags) {
                    seq_num = ntohl(tcp_hdr_received->seq_num);
                    ack_num = ntohl(tcp_hdr_received->ack_num);

                    unsigned short receivedMss = this->CheckMSS(packet_data);
                    if (receivedMss < this->mss) {
                        this->mss = receivedMss; // settle on the smallest mss
                    }

                    std::cout << "Valid SYN-ACK received." << std::endl;
                    return true;
                }
            }
        }
        else if (res == 0) {
            // pcap internal timeout - we loop and check elapsed time
        }
        else {
            // Error occurred
            std::cerr << "Error while waiting for SYN-ACK: " << pcap_geterr(this->handle) << std::endl;
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        if (now - start_time > timeout_duration) {
            std::cerr << "Timeout while waiting for SYN-ACK." << std::endl;
            return false;
        }
    }
}

// Closes the device
void TCPConnection::closeDevice() {
    /*
     * Closes and frees pcap resources.
     */

    pcap_close(this->handle);
    pcap_freealldevs(alldevs);
}


bool TCPConnection::handleIncomingFIN()
{
    /*
     * Handles a FIN packet from the peer (for graceful connection close).
     */

    // Step 1: Send ACK for the received FIN
    if (!sendTCPControlSegment(this->most_updated_remote_seq + 1, most_updated_seq, TCP_FLAG_ACK, false)) { // change to 0 if not relevant
        throw std::runtime_error("Failed to send ACK for received FIN");
    }
    
    // Step 2: Send our own FIN
    if (!sendTCPControlSegment(this->most_updated_remote_seq + 1, most_updated_seq, TCP_FLAG_FIN, false)) {
        throw std::runtime_error("Failed to send FIN");
    }

    // Step 3: Wait for the final ACK for our FIN
    if (!waitForSpecificACK(most_updated_seq, std::chrono::milliseconds(10000))) {
        std::cerr << "Timeout waiting for final ACK of our FIN." << std::endl;
        return false;
    }
    std::cout << "Final ACK received. Connection termination handled successfully." << std::endl;
    isConnected = false;

    return true;
}

bool TCPConnection::waitForSpecificACK(const unsigned int expectedAckNum, const std::chrono::milliseconds& timeout)
{
    /*
     * Waits for a specific ACK number from the peer.
     * Inputs:
     *   - expectedAckNum: required ACK
     *   - timeout: how long to wait
     * Output: true if received in time
     */

    auto startTime = std::chrono::steady_clock::now();

    TCPHeader incomingHeader;
    std::vector<u_char> incomingPacket;

    while (std::chrono::steady_clock::now() - startTime < timeout)
    {
        if (!receivePacket(incomingPacket) || !parseTCPHeader(incomingPacket, incomingHeader)) {
            continue; // Ignore malformed or unrelated packets
        }

        // Check if the incoming packet has the expected ACK number
        if (incomingHeader.flags == TCP_FLAG_ACK && incomingHeader.ack_num == expectedAckNum) {
            std::cout << "Received expected ACK: " << expectedAckNum << std::endl;
            return true;
        }
    }

    std::cerr << "Timeout waiting for ACK: " << expectedAckNum << std::endl;
    return false;
}

unsigned int TCPConnection::generateISN() const
{
    /*
     * Generates a random initial sequence number.
     */

    // Use a high-resolution clock as a seed for randomness
    auto now = std::chrono::high_resolution_clock::now();
    auto seed = static_cast<unsigned int>(now.time_since_epoch().count());

    // Create a random number generator
    std::mt19937 generator(seed); // Mersenne Twister engine
    std::uniform_int_distribution<unsigned int> distribution(0, UINT32_MAX);

    // Generate a random 32-bit ISN
    return distribution(generator);
}

unsigned short TCPConnection::CheckMSS(const unsigned char* packet_data)
{
    /*
     * Extracts the MSS option from TCP header options if present.
     * Output: MSS value
     */

    // TCP header pointer (skip Ethernet and IP headers)
    TCPHeader* tcp_hdr = (TCPHeader*)(packet_data + ETHERNET_HEADER_LEN + IP_HDR_LEN);

    // Calculate the length of the TCP header, considering the options field
    u_char data_offset = tcp_hdr->data_offset; // Data offset in 4-byte units
    size_t tcp_header_len = data_offset * 4;

    // TCP options start right after the standard header
    const unsigned char* options = packet_data + ETHERNET_HEADER_LEN + IP_HDR_LEN + sizeof(TCPHeader);

    // MSS option is 0x02 in TCP options
    const unsigned char* opt_ptr = options;
    while (opt_ptr < options + (tcp_header_len - sizeof(TCPHeader))) {
        u_char option_kind = *opt_ptr;
        u_char option_len = *(opt_ptr + 1);

        if (option_kind == 2) { // MSS option (Kind = 2)
            uint16_t mss = ntohs(*(uint16_t*)(opt_ptr + 2));
            std::cout << "Received MSS: " << mss << " bytes" << std::endl;
            return mss;
            break;
        }

        // Move to the next option (Kind + Length)
        opt_ptr += option_len;
    }
}

std::string TCPConnection::convertIpToString(const uint32_t ipAddress) const {
    /*
     * Converts a uint32_t IP to dotted-decimal string format.
     */

    char ipStr[INET_ADDRSTRLEN]; // Buffer to store the string format of the IP address
    inet_ntop(AF_INET, &ipAddress, ipStr, INET_ADDRSTRLEN); // Convert to string
    return std::string(ipStr); // Return as a std::string
}

unsigned short TCPConnection::calculateChecksum(unsigned short* buffer, int size) const
{
    /*
     * Calculates 16-bit checksum using a word buffer.
     */

    unsigned long checksum = 0;
    while (size > 1) {
        checksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) {
        checksum += *(unsigned char*)buffer;
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    return (unsigned short)(~checksum);
}

unsigned short TCPConnection::calculateChecksum(const std::vector<u_char>& data) const
{
    /*
     * Calculates 16-bit checksum using a word buffer.
     */

    uint32_t sum = 0;

    // Process the data in 16-bit words
    for (size_t i = 0; i < data.size(); i += 2) {
        uint16_t word = data[i] << 8; // Most significant byte
        if (i + 1 < data.size()) {
            word |= data[i + 1]; // Least significant byte
        }
        sum += word;

        // Handle carry
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // Finalize by adding any leftover carry
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    return static_cast<unsigned short>(~sum);
}