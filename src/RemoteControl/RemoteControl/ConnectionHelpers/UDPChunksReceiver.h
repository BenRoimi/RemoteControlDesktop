#pragma once
#include "../Connection/UDPConnection.h"
#include <vector>
#include <cstring>
#include <stdint.h>
#include "../Crypto/Crypto.h"

// Receiver side
class UDPChunksReceiver {
public:

    void handlePacket(const std::vector<uint8_t>& data);
    bool isComplete() const;
    std::vector<uint8_t> reconstructData();
    std::vector<uint8_t> reconstructAndDecryptData(HCRYPTPROV hAESKey);
    void resetHandling();

private:
    struct PacketInfo {
        std::vector<uint8_t> data;
        bool received = false;
    };

    struct PacketHeader {
        uint32_t sequenceNumber;
        uint32_t totalPackets;
        uint32_t payloadSize;
    };

    std::vector<PacketInfo> packets;
    size_t receivedCount = 0;
    size_t expectedPackets = 0;
};