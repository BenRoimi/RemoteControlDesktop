#pragma once
#include <string>
#include <vector>

struct ConnectionInitiationRequest {
	std::string password;
};

struct AesKeyRequest {
	std::vector<unsigned char> publicRsaKey;
};

struct FileTransmissionRequest {
	size_t fileSize;
	std::string fileName;
};