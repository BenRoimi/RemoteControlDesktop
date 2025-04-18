#pragma once
#include "../Connection/UDPConnection.h"
#include <vector>
#include <cstring>
#include <stdint.h>
#include "../Crypto/Crypto.h"

class UDPChunksTransfer {
public:
    explicit UDPChunksTransfer(UDPConnection* conn) : connection(conn) {}

    UDPChunksTransfer();
    bool sendData(const std::vector<uint8_t>& data);
    bool sendEncryptedData(const std::vector<uint8_t>& data, HCRYPTPROV hAESKey);
    void setConnection(UDPConnection* conn);

private:
    static const size_t MAX_PAYLOAD_SIZE = 1400; // usually 1500 but left room for headers
    struct PacketHeader {
        uint32_t sequenceNumber;
        uint32_t totalPackets;
        uint32_t payloadSize;
    };

    UDPConnection* connection;
};