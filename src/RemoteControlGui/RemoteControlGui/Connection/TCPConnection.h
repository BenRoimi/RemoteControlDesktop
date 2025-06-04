#pragma once
#include "Connection.h"
#include <pcap.h>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <queue>

/*
 * Struct: TCPSegment
 * -------------------
 * Represents a single TCP segment in the custom TCP implementation.
 * Each segment includes the sequence number, data payload, ACK status,
 * send time (for timeout handling), and checksum for integrity.
 */
struct TCPSegment {
    unsigned int seq_num;
    std::vector<u_char> data;
    bool acknowledged = false;
    std::chrono::time_point<std::chrono::steady_clock> sent_time;
    unsigned short checksum;
};

/*
 * Class: TCPConnection
 * ---------------------
 * Implements a manual, raw-socket-based TCP stack using WinPcap/Npcap.
 * Provides connection setup, teardown, data sending/receiving, and segmentation/ACK logic.
 */
class TCPConnection : public Connection{
public:
    // Constructors / Destructor
    TCPConnection();
    TCPConnection(int srcPort, int dstPort, unsigned short mss_value);
    TCPConnection(int srcPort, int dstPort, unsigned short mss_value, Connection* other);
    ~TCPConnection();

    // Connection Management (3/4-Way Handshake)
    bool initializeConnection(const std::string& ipAddress);
    bool WaitForConnection();
    void closeConnection();
    void restartConnection();

    // Data Transmission
    bool sendData(const std::vector<uint8_t>& data);
    void startReceiving();
    void stopReceiving();

    // Data Retrieval
    bool isDataEmpty();
    std::vector<uint8_t> getData(int bytes);
    std::vector<uint8_t> getData();

    // helper Accessors
    std::string getDestIp();
    std::string getSrcIP();
    bool getIsConnected();

private:

    //======================//
    //   TCP State & Config //
    //======================//
    unsigned int most_updated_seq; // Last sequence number sent from this host (used for new segments)
    unsigned int most_updated_received_ack; // Highest ACK number received from remote host
    unsigned int most_updated_remote_seq; // Last sequence number received from the peer
    unsigned short mss; // Maximum Segment Size negotiated for this connection
    size_t window_size; // Simulated TCP receive window size (used for flow control)
    bool isConnected; // Indicates whether the connection is currently active

    //======================//
    //    Data Structures   //
    //======================//
    std::queue<uint8_t> receivedDataStreamQueue; // Fully reassembled application data (byte stream)
    std::queue<TCPSegment> segmentQueue; // Queue for received but unprocessed TCP segments
    std::queue<TCPSegment> segmentsToSendQueue; // Queue of segments ready to be sent
    std::queue<TCPSegment> SentSegmentsQueue; // Queue of segments sent but awaiting ACK

    //======================//
    //   Multithreading     //
    //======================//
    std::mutex receivedDataStreamQueueMutex; // Protects access to receivedDataStreamQueue
    std::mutex queueMutex; // Protects access to segmentQueue
    std::mutex sendQueueMutex; // Protects access to segmentsToSendQueue
    std::mutex SentQueueMutex; // Protects access to SentSegmentsQueue
    std::mutex dataMutex; // General mutex for shared state control
    std::condition_variable queueCondition; // Notifies when new data arrives for processing

    std::thread receivingThread; // Background thread for receiving packets
    std::thread printingThread; // Optional thread for debugging/logging (not used in core logic)
    bool stopSendingFlag; // Signal flag to terminate sending threads

    //======================//
    //    Main Operations   //
    //======================//
    void receiveData();
    void processSegments(std::vector<TCPSegment>& receivedSegments, std::vector<u_char>& reconstructedPayload);
    void segmentPayloadSeperator(const std::vector<u_char>& payload_data, std::queue<TCPSegment>& segments);
    std::vector<u_char> reconstructPayload(std::vector<TCPSegment>& orderedSegments, unsigned int& expectedSeqNum);

    //======================//
    //     Sending Logic    //
    //======================//
    void senderThreadFunc();
    void CheckRetransmissionThreadFunc();
    void sendAckUpdateThreadFunc();
    bool sendSegment(const std::vector<u_char>& packet);
    bool waitForACKs(std::vector<TCPSegment>& segments, const std::chrono::milliseconds& timeout);
    bool waitForSpecificACK(const unsigned int expectedAckNum, const std::chrono::milliseconds& timeout);
    bool sendTCPControlSegment(const unsigned int ackNum, const unsigned int seqNum, const uint8_t tcpFlags, bool sendMss);

    //======================//
    //     Packet Parsing   //
    //======================//
    bool receivePacket(std::vector<u_char>& rawPacket);
    bool parseSegment(const std::vector<u_char>& rawSegment, TCPSegment& segment);
    bool extractTcpHeader(const std::vector<u_char>& rawSegment, TCPHeader& tcpHeader);
    bool parseTCPHeader(const std::vector<u_char>& rawPacket, TCPHeader& header);
    bool isPacketFromSource(const u_char* packet);
    unsigned short CheckMSS(const unsigned char* packet_data);

    //======================//
    //    Segment Creation  //
    //======================//
    bool createSegment(const TCPSegment& segment, std::vector<u_char>& rawSegment);
    std::vector<u_char> serializeHeadersAndPayload(const EthernetHeader& ethHeader, const IPHeader& ipHeader, const TCPHeader& tcpHeader, const std::vector<u_char>& payload, const std::vector<u_char>& tcpOptions);

    //======================//
    //     Header Creation  //
    //======================//
    void createEthernetHeader(EthernetHeader& eth_hdr, const unsigned char* src_mac, const unsigned char* dest_mac, const uint16_t ethertype) const;
    void createIPHeader(IPHeader& ip_hdr, const std::string& src_ip, const std::string& dest_ip, const uint8_t ttl, const uint8_t protocol, const uint16_t flags_offset, const uint16_t total_len) const;
    void createTCPHeader(TCPHeader& tcp_hdr, const uint16_t src_port, const uint16_t dest_port, const uint32_t seq_num, const uint32_t ack_num, const uint8_t flags, const uint16_t window_size, const size_t options_size, const unsigned short checksum) const;
    void createPseudoHeader(PseudoHeader& psh, const std::string& src_ip, const std::string& dest_ip, uint8_t protocol, uint16_t tcp_length) const;

    //======================//
    //     Device I/O       //
    //======================//
    bool openDevice();
    void closeDevice();
    bool waitForSYNACK(uint32_t expected_src_ip, const uint32_t expected_dest_ip, const uint16_t expected_src_port, const uint16_t expected_dest_port, const uint8_t expected_flags, uint32_t& seq_num, uint32_t& ack_num);
    bool handleIncomingFIN();

    //======================//
    //     Utility          //
    //======================//
    unsigned short calculateChecksum(unsigned short* buffer, int size) const;
    unsigned short calculateChecksum(const std::vector<u_char>& data) const;
    unsigned int generateISN() const;
    std::string convertIpToString(const uint32_t ipAddress) const;
    size_t calculateBufferSent();
};
