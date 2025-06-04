#pragma once
#include "Requests/Requests.h"
#include "Responses/Responses.h"
#include "./Codes.h"
#include "../Connection/TCPConnection.h"
#include "../Crypto/Crypto.h"

class JsonPacketDeserializer
{
public:
	JsonPacketDeserializer() = delete;
	
	static  std::vector<unsigned char> getFullMessageFromTcpConnectionStream(TCPConnection& connection, HCRYPTPROV hAESKey);
	static  std::vector<unsigned char> getFullMessageFromTcpConnectionStream(TCPConnection& connection);

	// Requests
	static ConnectionInitiationRequest deserializeConnectionRequest(const std::vector<unsigned char> buffer);
	static AesKeyRequest deserializeAesKeyRequest(const std::vector<unsigned char> buffer);
	static FileTransmissionRequest deserializeFileTransmissionRequest(const std::vector<unsigned char> buffer);

	// Responses
	static ErrorResponse deserializeErrorResponse(const std::vector<unsigned char> buffer);
	static AesKeyResponse deserializeAesKeyResponse(const std::vector<unsigned char> buffer);
	static SettingsExchangeResponse deserializeSettingsResponse(const std::vector<unsigned char>& buffer);
	static Action deserializeActionResponse(const std::vector<unsigned char>& buffer);
	static std::vector<unsigned char> deserializeImageResponse(const std::vector<unsigned char>& buffer);
	static FileTransmissionResponse deserializeFileTransmissionResponse(const std::vector<unsigned char> buffer);
	static std::vector<unsigned char> deserializeFileData(const std::vector<unsigned char>& buffer);

	static int getMessageCode(const std::vector<unsigned char>& buffer);

private:
	static std::pair<int, std::string> splitRequest(const std::vector<unsigned char>& buffer);

};

