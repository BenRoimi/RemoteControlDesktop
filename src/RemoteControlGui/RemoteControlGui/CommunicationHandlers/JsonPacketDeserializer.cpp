#include "JsonPacketDeserializer.h"
#include "../../../../dep/json.hpp"
#include "./Codes.h"

using json = nlohmann::json;

std::vector<unsigned char> JsonPacketDeserializer::getFullMessageFromTcpConnectionStream(TCPConnection& connection, HCRYPTPROV hAESKey)
{
    std::vector<unsigned char> fullMessage;

    if (!connection.isDataEmpty())
    {
        std::vector<unsigned char> encryptedMessage;
        std::vector<unsigned char> decryptedMessage;

        // Read the first 4 bytes to determine the size
        std::vector<unsigned char> sizeBuffer = connection.getData(4);
        if (sizeBuffer.size() < 4)
        {
            throw std::runtime_error("Failed to read message size from TCP stream");
        }

        // Convert the first 4 bytes to an integer (big-endian format)
        uint32_t EncryptedMessageSize = (sizeBuffer[0] << 24) | (sizeBuffer[1] << 16) |
            (sizeBuffer[2] << 8) | sizeBuffer[3];

        // Read the remaining data until the full message size is reached
        while (encryptedMessage.size() < EncryptedMessageSize)
        {
            int remainingBytes = EncryptedMessageSize - encryptedMessage.size();
            std::vector<unsigned char> chunk = connection.getData(remainingBytes); // add here try and expect!!

            if (chunk.empty())
            {
                throw std::runtime_error("Connection interrupted or no more data available");
            }

            // Append the chunk to the encryptedMessage
            encryptedMessage.insert(encryptedMessage.end(), chunk.begin(), chunk.end());
        }

        Crypto::DecryptAES(encryptedMessage, decryptedMessage, hAESKey);
        
        int len = decryptedMessage.size();
        char* numberStr = static_cast<char*>(static_cast<void*>(&len));

        fullMessage.push_back(numberStr[3]);
        fullMessage.push_back(numberStr[2]);
        fullMessage.push_back(numberStr[1]);
        fullMessage.push_back(numberStr[0]);

        fullMessage.insert(fullMessage.end(), decryptedMessage.begin(), decryptedMessage.end());
    }

    return fullMessage;
}

std::vector<unsigned char> JsonPacketDeserializer::getFullMessageFromTcpConnectionStream(TCPConnection& connection)
{
    std::vector<unsigned char> fullMessage;

    // Ensure there is data in the stream
    if (!connection.isDataEmpty())
    {
        // Read the first 4 bytes to determine the size
        std::vector<unsigned char> sizeBuffer = connection.getData(4);
        if (sizeBuffer.size() < 4)
        {
            throw std::runtime_error("Failed to read message size from TCP stream");
        }

        uint32_t messageSize = (sizeBuffer[0] << 24) | (sizeBuffer[1] << 16) |
            (sizeBuffer[2] << 8) | sizeBuffer[3];

        fullMessage.insert(fullMessage.end(), sizeBuffer.begin(), sizeBuffer.end());

        // Read the remaining data until the full message size is reached
        while (fullMessage.size() < messageSize + 4)
        {
            int remainingBytes = messageSize - fullMessage.size() + 4;
            std::vector<unsigned char> chunk = connection.getData(remainingBytes);

            if (chunk.empty())
            {
                throw std::runtime_error("Connection interrupted or no more data available");
            }

            // Append the chunk to the full message
            fullMessage.insert(fullMessage.end(), chunk.begin(), chunk.end());
        }
    }

    return fullMessage;

}

ConnectionInitiationRequest JsonPacketDeserializer::deserializeConnectionRequest(const std::vector<unsigned char> buffer)
{
    std::pair<int, std::string> splitRequest = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitRequest.second);

    ConnectionInitiationRequest connectionInitiationRequest;
    connectionInitiationRequest.password = j["password"];

    return connectionInitiationRequest;

}

ErrorResponse JsonPacketDeserializer::deserializeErrorResponse(const std::vector<unsigned char> buffer)
{
    std::pair<int, std::string> splitRequest = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitRequest.second);

    ErrorResponse errorResponse;
    errorResponse.message = j["message"];

    return errorResponse;
}

AesKeyResponse JsonPacketDeserializer::deserializeAesKeyResponse(const std::vector<unsigned char> buffer)
{
    std::pair<int, std::string> splitRequest = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitRequest.second);

    AesKeyResponse aesKeyResponse;
    aesKeyResponse.aesKey = j.at("aesKey").get<std::vector<unsigned char>>();

    return aesKeyResponse;
}

AesKeyRequest JsonPacketDeserializer::deserializeAesKeyRequest(const std::vector<unsigned char> buffer)
{
    std::pair<int, std::string> splitRequest = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitRequest.second);

    AesKeyRequest aesKeyRequest;
    aesKeyRequest.publicRsaKey = j.at("publicRsaKey").get<std::vector<unsigned char>>();

    return aesKeyRequest;
}

FileTransmissionRequest JsonPacketDeserializer::deserializeFileTransmissionRequest(const std::vector<unsigned char> buffer)
{
    std::pair<int, std::string> splitResponse = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitResponse.second);

    FileTransmissionRequest response;
    response.fileName = j.at("fileName").get<std::string>();
    response.fileSize = j.at("fileSize").get<size_t>();

    return response;
}

SettingsExchangeResponse JsonPacketDeserializer::deserializeSettingsResponse(const std::vector<unsigned char>& buffer)
{
    std::pair<int, std::string> splitResponse = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitResponse.second);

    SettingsExchangeResponse response;
    response.screenWidth = j.at("screenWidth").get<int>();
    response.screenHeight = j.at("screenHeight").get<int>();
    response.colorDepth = j.at("colorDepth").get<int>();
    response.qualityScale = j.at("qualityScale").get<double>();
    response.virtualChannelsToRemove = j.at("virtualChannelsToRemove").get<std::vector<unsigned int>>();

    return response;
}


Action JsonPacketDeserializer::deserializeActionResponse(const std::vector<unsigned char>& buffer)
{
    std::pair<int, std::string> splitResponse = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitResponse.second);

    Action response;
    response.type = static_cast<ActionType>(j["type"]);
    switch (response.type) {
    case ActionType::MouseMove: {
        response.x = j.at("x").get<int>();
        response.y = j.at("y").get<int>();
        break;
    }
    case ActionType::MouseClick: {
        response.x = j.at("x").get<int>();
        response.y = j.at("y").get<int>();
        response.button = static_cast<MouseAction>(j["button"]);
        break;
    }

    case ActionType::KeyPress: {
        response.key = j["key"].get<int>();
        break;
    }
    default:
        std::cerr << "Unknown action type received.\n";
        break;
    }

    return response;
}

std::vector<unsigned char> JsonPacketDeserializer::deserializeImageResponse(const std::vector<unsigned char>& buffer)
{
    std::pair<int, std::string> splitResponse = JsonPacketDeserializer::splitRequest(buffer);

    std::string imageStr = splitResponse.second;
    std::vector<unsigned char> vec(imageStr.begin(), imageStr.end());
    return vec;
}

FileTransmissionResponse JsonPacketDeserializer::deserializeFileTransmissionResponse(const std::vector<unsigned char> buffer)
{
    std::pair<int, std::string> splitsponse = JsonPacketDeserializer::splitRequest(buffer);

    json j = json::parse(splitsponse.second);

    FileTransmissionResponse response;
    response.accepted = j.at("accepted").get<bool> ();

    return response;
}

std::vector<unsigned char> JsonPacketDeserializer::deserializeFileData(const std::vector<unsigned char>& buffer)
{
    std::pair<int, std::string> splitResponse = JsonPacketDeserializer::splitRequest(buffer);

    std::string fileDataStr = splitResponse.second;
    std::vector<unsigned char> vec(fileDataStr.begin(), fileDataStr.end());
    return vec;
}

int JsonPacketDeserializer::getMessageCode(const std::vector<unsigned char>& buffer)
{
    return buffer[4];
}

std::pair<int, std::string> JsonPacketDeserializer::splitRequest(const std::vector<unsigned char>& buffer)
{
    std::pair<int, std::string> request;

    // get data size
    char sizeArr[4];
    sizeArr[3] = buffer[0];
    sizeArr[2] = buffer[1];
    sizeArr[1] = buffer[2];
    sizeArr[0] = buffer[3];

    int size = *((unsigned int*)sizeArr) -1; // minus 1 to remove the codeId

    unsigned char id = buffer[4];
    request.first = (int)id;

    // get the data
    std::string data;
    data.resize(size);

    std::copy(buffer.begin() + 5, buffer.begin() + 5 + size, data.begin()); 

    request.second = data;

    return request;

}