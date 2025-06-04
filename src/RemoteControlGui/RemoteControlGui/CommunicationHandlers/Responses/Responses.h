#pragma once
#include "..//Codes.h"

struct ErrorResponse {
    std::string message;
};

struct AesKeyResponse {
    std::vector<unsigned char> aesKey;
};

struct SettingsExchangeResponse {
    int screenWidth;
    int screenHeight;
    int colorDepth;
    double qualityScale;
    std::vector<unsigned int> virtualChannelsToRemove;
};

struct FileTransmissionResponse {
    bool accepted;
};