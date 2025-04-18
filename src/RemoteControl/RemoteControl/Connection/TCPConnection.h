#pragma once
#include "Connection.h"
#include <pcap.h>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <queue>

struct TCPSegment {
    unsigned int seq_num;
    std::vector<u_char> data;
    bool acknowledged = false;
    std::chrono::time_point<std::chrono::steady_clock> sent_time;
    unsigned short checksum;
};


class TCPConnection : public Connection{
public:
    TCPConnection();
    TCPConnection(int srcPort, int dstPort, unsigned short mss_value);
    ~TCPConnection();

    bool initializeConnection(const std::string& ipAddress);
    bool WaitForConnection();

    void closeConnection();

    bool sendData(const std::vector<uint8_t>& data);
    void startReceiving();
    void stopReceiving();

    bool isDataEmpty();
    std::vector<uint8_t> getData(int bytes);
    std::vector<uint8_t> getData();

    std::string getDestIp();
    bool getIsConnected();
private:
    // The data received:
    std::queue<uint8_t> receivedDataStreamQueue;
    std::mutex receivedDataStreamQueueMutex;

    // TCP protocol info
    unsigned int most_updated_seq;
    unsigned int most_updated_received_ack; // field for ack from the other user checking
    unsigned int most_updated_remote_seq;
    unsigned short mss;
    size_t window_size;
    // Multithreading info
    std::thread receivingThread;
    std::thread printingThread;
    bool isConnected;
    std::mutex dataMutex;

    // receiving Thread-safe queue for storing segments to be processed
    std::queue<TCPSegment> segmentQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;

    // Sending threads
    std::queue<TCPSegment> segmentsToSendQueue;
    std::mutex sendQueueMutex;
    std::queue<TCPSegment> SentSegmentsQueue;
    std::mutex SentQueueMutex;
    bool stopSendingFlag;

    void senderThreadFunc();
    void CheckRetransmissionThreadFunc();
    void sendAckUpdateThreadFunc();

    size_t calculateBufferSent();

    unsigned short calculateChecksum(unsigned short* buffer, int size) const;
    unsigned short calculateChecksum(const std::vector<u_char>& data) const;
    // Main functions
    void receiveData();
    void processSegments(std::vector<TCPSegment>& receivedSegments, std::vector<u_char>& reconstructedPayload);
    
    void segmentPayloadSeperator(const std::vector<u_char>& payload_data, std::queue<TCPSegment>& segments);
    std::vector<u_char> reconstructPayload(std::vector<TCPSegment>& orderedSegments, unsigned int& expectedSeqNum);

    bool createSegment(const TCPSegment& segment, std::vector<u_char>& rawSegment);
    bool sendSegment(const std::vector<u_char>& packet);
    bool receivePacket(std::vector<u_char>& rawPacket);
    bool parseSegment(const std::vector<u_char>& rawSegment, TCPSegment& segment);
    bool extractTcpHeader(const std::vector<u_char>& rawSegment, TCPHeader& tcpHeader);
    std::vector<u_char> serializeHeadersAndPayload(const EthernetHeader& ethHeader, const IPHeader& ipHeader, const TCPHeader& tcpHeader, const std::vector<u_char>& payload, const std::vector<u_char>& tcpOptions);
    bool waitForACKs(std::vector<TCPSegment>& segments, const std::chrono::milliseconds& timeout);
    bool sendTCPControlSegment(const unsigned int ackNum, const unsigned int seqNum, const uint8_t tcpFlags, bool sendMss);
    bool isPacketFromSource(const u_char* packet);
    bool parseTCPHeader(const std::vector<u_char>& rawPacket, TCPHeader& header);
    std::string convertIpToString(const uint32_t ipAddress) const;

    bool openDevice();
    void createEthernetHeader(EthernetHeader& eth_hdr, const unsigned char* src_mac, const unsigned char* dest_mac, const uint16_t ethertype) const;
    void createIPHeader(IPHeader& ip_hdr, const std::string& src_ip, const std::string& dest_ip, const uint8_t ttl, const uint8_t protocol, const uint16_t flags_offset, const uint16_t total_len) const;
    void createTCPHeader(TCPHeader& tcp_hdr, const uint16_t src_port, const uint16_t dest_port, const uint32_t seq_num, const uint32_t ack_num, const uint8_t flags, const uint16_t window_size, const size_t options_size, const unsigned short checksum) const;
    void createPseudoHeader(PseudoHeader& psh, const std::string& src_ip, const std::string& dest_ip, uint8_t protocol, uint16_t tcp_length) const;
    bool waitForSYNACK(uint32_t expected_src_ip, const uint32_t expected_dest_ip, const uint16_t expected_src_port, const uint16_t expected_dest_port, const uint8_t expected_flags, uint32_t& seq_num, uint32_t& ack_num);
    void closeDevice();

    bool handleIncomingFIN(); // function to handle connection termination from the other side
    bool waitForSpecificACK(const unsigned int expectedAckNum, const std::chrono::milliseconds& timeout);

    unsigned int generateISN() const;
    unsigned short CheckMSS(const unsigned char* packet_data);
};
