#pragma once
#include <string>
#include "../Connection/TCPConnection.h"
#include "../Connection/UDPConnection.h"
#include "../CommunicationHandlers/Codes.h"
#include "../CommunicationHandlers/Requests/Requests.h"
#include "../CommunicationHandlers/Responses/Responses.h"
#include "../CommunicationHandlers/VirtualChannelManager.h"
#include "../CommunicationHandlers/JsonPacketDeserializer.h"
#include "../CommunicationHandlers/JsonPacketSerializer.h"
#include "../ConnectionHelpers/UDPChunksReceiver.h"
#include "../Compressor/H264Decoder.h"
#include <windows.h>
#include <gdiplus.h>
#include <mmsystem.h>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "gdiplus.lib")
using namespace Gdiplus;


#define MSS 1460
#define TCPSRCPORT 4321
#define TCPDSTPORT 1234
#define UDPSRCPORTSCREEN 8765
#define UDPDSTPORTSCREEN 5678
#define UDPSRCPORTAUDIO 8777
#define UDPDSTPORTAUDIO 5666

#define SAMPLE_RATE 48000
#define NUM_CHANNELS 1
#define BITS_PER_SAMPLE 16
#define FRAMES_PER_BUFFER 1024

class Client {

public:

    Client();
    bool connect(const std::string& ipAddr, const std::string& password); // Connecting to server

private:

    // Object fields
    TCPConnection tcpConnection;
    UDPConnection udpScreenConnection;
    UDPConnection udpAudioConnection;

    NegotiationState state;
    bool hasExited;
    
    std::vector<BYTE> serverPublicRsaKey;
    HCRYPTPROV hAESKey;
    HCRYPTPROV hProv;

    // Settings field
    int serverScreenWidth;
    int serverScreenHeight;
    int clientScreenWidth;
    int clientScreenHeight;
    int colorDepth;
    double qualityScale;
    std::string ipAddr; // server ip addres

    // Nagotiation functions
    bool initiateConnection(const std::string& password);
    void initiateSettingsExchange();
        
    // Data stream handler
    void updateChannelsData(); 

    // Input channel funcs
    void lunchKeyboardThread();
    void keyboardThread();
    void sendInput(Action action);
    static void mouseCallback(int event, int x, int y, int flags, void* userdata);
    void exitInputThread();

    // Output channel
    void recieveScreenshotsThread();
    void lunchScreenshotsThread();
    void showScreenshotImagesThread();
    std::queue< std::vector<uint8_t>> screenshotsQueue;
    std::mutex screenshotQueueMutex;

    // Audio channel
    void startReceivingAudio();
    
    // Threads to join in the end
    std::vector<std::thread> threads;

};
