#include "UDPChunksReceiver.h"

void UDPChunksReceiver::handlePacket(const std::vector<uint8_t>& packetData)
{
    if (packetData.size() < sizeof(PacketHeader)) {
        return;
    }

    const PacketHeader* header = reinterpret_cast<const PacketHeader*>(packetData.data());

    // Initialize packets vector if this is the first packet
    if (packets.empty()) {
        packets.resize(header->totalPackets);
        expectedPackets = header->totalPackets;
    }

    // Store packet data
    if (header->sequenceNumber < packets.size() && !packets[header->sequenceNumber].received) {
        const uint8_t* payload = packetData.data() + sizeof(PacketHeader);
        size_t payloadSize = header->payloadSize;

        packets[header->sequenceNumber].data.assign(payload, payload + payloadSize);
        packets[header->sequenceNumber].received = true;
        receivedCount++;
    }
}

bool UDPChunksReceiver::isComplete() const
{
    return receivedCount == expectedPackets;
}

std::vector<uint8_t> UDPChunksReceiver::reconstructData()
{
    if (!isComplete()) {
        return std::vector<uint8_t>();
    }

    // Calculate total size
    size_t totalSize = 0;
    for (const auto& packet : packets) {
        totalSize += packet.data.size();
    }

    // Assemble data
    std::vector<uint8_t> data;
    data.reserve(totalSize);

    for (const auto& packet : packets) {
        data.insert(data.end(), packet.data.begin(), packet.data.end());
    }

    return data;
}

std::vector<uint8_t> UDPChunksReceiver::reconstructAndDecryptData(HCRYPTPROV hAESKey)
{
    if (!isComplete()) {
        return std::vector<uint8_t>();
    }

    // Calculate total size
    size_t totalSize = 0;
    for (const auto& packet : packets) {
        totalSize += packet.data.size();
    }

    // Assemble data
    std::vector<uint8_t> encryptedMessage;
    encryptedMessage.reserve(totalSize);

    for (const auto& packet : packets) {
        encryptedMessage.insert(encryptedMessage.end(), packet.data.begin(), packet.data.end());
    }

    std::vector<unsigned char> decryptedMessage;

    Crypto::DecryptAES(encryptedMessage, decryptedMessage, hAESKey);

    return decryptedMessage;
}

void UDPChunksReceiver::resetHandling()
{
    this->packets.clear();
    this->receivedCount = 0;
    this->expectedPackets = 0;
}
