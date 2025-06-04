#include "../CommunicationHandlers/JsonPacketSerializer.h"
#include "../../../../dep/json.hpp"
#include <Windows.h>

using json = nlohmann::json;

std::vector<unsigned char> JsonPacketSerializer::serializeShortCodeMessage(const CodeId code, HCRYPTPROV hAESKey)
{
    return JsonPacketSerializer::combinePacket(code, {}, hAESKey);
}

std::vector<unsigned char> JsonPacketSerializer::serializeShortCodeMessage(const CodeId code)
{
    return JsonPacketSerializer::combinePacket(code, {});
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const ErrorResponse& errorResponse, HCRYPTPROV hAESKey)
{
    json j;
    j["message"] = errorResponse.message;
    std::string dump = j.dump();

    return JsonPacketSerializer::combinePacket(CodeId::Error, dump, hAESKey);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const ErrorResponse& errorResponse)
{
    json j;
    j["message"] = errorResponse.message;
    std::string dump = j.dump();

    return JsonPacketSerializer::combinePacket(CodeId::Error, dump);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const ConnectionInitiationRequest& connectionInitiationRequest)
{
    json j;
    j["password"] = connectionInitiationRequest.password;
    std::string dump = j.dump();

    return JsonPacketSerializer::combinePacket(CodeId::Connect, dump);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const AesKeyRequest& connectionAcceptedResponse)
{
    json j;
    j["publicRsaKey"] = connectionAcceptedResponse.publicRsaKey;
    std::string dump = j.dump();

    return JsonPacketSerializer::combinePacket(CodeId::AesKeyRequest, dump);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const AesKeyResponse& aesKeyResponse)
{
    json j;
    j["aesKey"] = aesKeyResponse.aesKey;
    std::string dump = j.dump();

    return JsonPacketSerializer::combinePacket(CodeId::AesKeyResponse, dump);
}

std::vector<unsigned char> JsonPacketSerializer::combinePacket(const CodeId code, const std::string& message, HCRYPTPROV hAESKey)
{
    std::vector<unsigned char> buffer;
    std::vector<unsigned char> plaintextMessage;
    plaintextMessage.push_back((unsigned char)code);
    plaintextMessage.insert(plaintextMessage.end(), message.begin(), message.end());

    std::vector<BYTE> EncryptedMessage;

    Crypto::EncryptAES(plaintextMessage, EncryptedMessage, hAESKey);

    int len = EncryptedMessage.size();
    char* numberStr = static_cast<char*>(static_cast<void*>(&len));

    buffer.push_back(numberStr[3]);
    buffer.push_back(numberStr[2]);
    buffer.push_back(numberStr[1]);
    buffer.push_back(numberStr[0]);

    buffer.insert(buffer.end(), EncryptedMessage.begin(), EncryptedMessage.end());

    return buffer;
}

std::vector<unsigned char> JsonPacketSerializer::combinePacket(const CodeId code, const std::string& message)
{
    std::vector<unsigned char> buffer;

    int len = message.size() + 1;
    char* numberStr = static_cast<char*>(static_cast<void*>(&len));

    buffer.push_back(numberStr[3]);
    buffer.push_back(numberStr[2]);
    buffer.push_back(numberStr[1]);
    buffer.push_back(numberStr[0]);

    buffer.push_back((unsigned char)code);

    buffer.insert(buffer.end(), message.begin(), message.end());

    return buffer;

}

std::vector<unsigned char> JsonPacketSerializer::serialize(const SettingsExchangeResponse& settingsExchangeResponse, HCRYPTPROV hAESKey)
{
    json j;
    j["screenWidth"] = settingsExchangeResponse.screenWidth;
    j["screenHeight"] = settingsExchangeResponse.screenHeight;
    j["colorDepth"] = settingsExchangeResponse.colorDepth;
    j["qualityScale"] = settingsExchangeResponse.qualityScale;
    j["virtualChannelsToRemove"] = settingsExchangeResponse.virtualChannelsToRemove;

    std::string dump = j.dump();
    return JsonPacketSerializer::combinePacket(CodeId::SettingsExchangeResponse, dump, hAESKey);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const Action& action, HCRYPTPROV hAESKey)
{
    json j;
    j["type"] = action.type;
    j["button"] = action.button;
    j["key"] = action.key;
    j["x"] = action.x;
    j["y"] = action.y;

    std::string dump = j.dump();
    return JsonPacketSerializer::combinePacket(CodeId::SendAction, dump, hAESKey);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const std::vector<unsigned char>& image, HCRYPTPROV hAESKey)
{
    std::string strImg(image.begin(), image.end());
    return JsonPacketSerializer::combinePacket(CodeId::SendScreenshot, strImg, hAESKey);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const FileTransmissionRequest& fileTransmissionRequest, HCRYPTPROV hAESKey)
{
    json j;
    j["fileName"] = fileTransmissionRequest.fileName;
    j["fileSize"] = fileTransmissionRequest.fileSize;

    std::string dump = j.dump();
    return JsonPacketSerializer::combinePacket(CodeId::FileTransmissionRequest, dump, hAESKey);
}

std::vector<unsigned char> JsonPacketSerializer::serialize(const FileTransmissionResponse& fileTransmissionResponse, HCRYPTPROV hAESKey)
{
    json j;
    j["accepted"] = fileTransmissionResponse.accepted;

    std::string dump = j.dump();
    return JsonPacketSerializer::combinePacket(CodeId::FileTransmissionResponse, dump, hAESKey);
}

std::vector<unsigned char> JsonPacketSerializer::serializeFileData(const std::vector<unsigned char>& data, HCRYPTPROV hAESKey)
{
    std::string strImg(data.begin(), data.end());
    return JsonPacketSerializer::combinePacket(CodeId::FileData, strImg, hAESKey);
}
