#include "UDPChunksTransfer.h"
#include <chrono>
#include <thread>

UDPChunksTransfer::UDPChunksTransfer()
{
}

bool UDPChunksTransfer::sendData(const std::vector<uint8_t>& data)
{
    const size_t totalSize = data.size();
    const size_t totalPackets = (totalSize + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;

    // Send each chunk
    for (size_t i = 0; i < totalPackets; i++) {
        // Calculate payload size for this packet
        size_t offset = i * MAX_PAYLOAD_SIZE;
        size_t remainingBytes = totalSize - offset;
        size_t payloadSize = (((remainingBytes) < (MAX_PAYLOAD_SIZE)) ? (remainingBytes) : (MAX_PAYLOAD_SIZE));

        // Prepare packet with header
        std::vector<uint8_t> packet(sizeof(PacketHeader) + payloadSize);
        PacketHeader header{
            static_cast<uint32_t>(i),           // sequenceNumber
            static_cast<uint32_t>(totalPackets), // totalPackets
            static_cast<uint32_t>(payloadSize)   // payloadSize
        };

        // Copy header and payload
        memcpy(packet.data(), &header, sizeof(PacketHeader));
        memcpy(packet.data() + sizeof(PacketHeader),
            data.data() + offset,
            payloadSize);

        // Send packet
        if (!connection->sendData(packet)) {
            return false;
        }

        // Add a small delay between packets to prevent overwhelming the network
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return true;
}

bool UDPChunksTransfer::sendEncryptedData(const std::vector<uint8_t>& data, HCRYPTPROV hAESKey)
{
    std::vector<BYTE> EncryptedMessage;

    Crypto::EncryptAES(data, EncryptedMessage, hAESKey);

    const size_t totalSize = EncryptedMessage.size();
    const size_t totalPackets = (totalSize + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;

    // Send each chunk
    for (size_t i = 0; i < totalPackets; i++) {
        // Calculate payload size for this packet
        size_t offset = i * MAX_PAYLOAD_SIZE;
        size_t remainingBytes = totalSize - offset;
        size_t payloadSize = (((remainingBytes) < (MAX_PAYLOAD_SIZE)) ? (remainingBytes) : (MAX_PAYLOAD_SIZE));

        // Prepare packet with header
        std::vector<uint8_t> packet(sizeof(PacketHeader) + payloadSize);
        PacketHeader header{
            static_cast<uint32_t>(i),           // sequenceNumber
            static_cast<uint32_t>(totalPackets), // totalPackets
            static_cast<uint32_t>(payloadSize)   // payloadSize
        };

        // Copy header and payload
        memcpy(packet.data(), &header, sizeof(PacketHeader));
        memcpy(packet.data() + sizeof(PacketHeader),
            EncryptedMessage.data() + offset,
            payloadSize);

        // Send packet
        if (!connection->sendData(packet)) {
            return false;
        }

        // Add a small delay between packets to prevent overwhelming the network
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void UDPChunksTransfer::setConnection(UDPConnection* conn)
{
    connection = conn;
}
