#pragma once
#include "Requests/Requests.h"
#include "Responses/Responses.h"
#include "./Codes.h"
#include "../Crypto/Crypto.h"

class JsonPacketSerializer
{
public:
	JsonPacketSerializer() = delete;
	static std::vector<unsigned char> serializeShortCodeMessage(const CodeId code, HCRYPTPROV hAESKey);
	static std::vector<unsigned char> serializeShortCodeMessage(const CodeId code);

	static std::vector<unsigned char> serialize(const ErrorResponse& errorResponse, HCRYPTPROV hAESKey);
	static std::vector<unsigned char> serialize(const ErrorResponse& errorResponse);

	static std::vector<unsigned char> serialize(const ConnectionInitiationRequest& connectionInitiationRequest);

	static std::vector<unsigned char> serialize(const AesKeyRequest& aesKeyRequest);

	static std::vector<unsigned char> serialize(const AesKeyResponse& aesKeyResponse);

	static std::vector<unsigned char> serialize(const SettingsExchangeResponse& settingsExchangeResponse, HCRYPTPROV hAESKey);
	static std::vector<unsigned char> serialize(const Action& action, HCRYPTPROV hAESKey);
	static std::vector<unsigned char> serialize(const std::vector<unsigned char>& image, HCRYPTPROV hAESKey);

private:
	static std::vector<unsigned char> combinePacket(const CodeId code, const std::string& message, HCRYPTPROV hAESKey);
	static std::vector<unsigned char> combinePacket(const CodeId code, const std::string& message);
};

