#pragma once
#include <opencv2/opencv.hpp>
#include <string>
#include "../Connection/TCPConnection.h"
#include "../Connection/UDPConnection.h"
#include "../CommunicationHandlers/Codes.h"
#include "../CommunicationHandlers/Requests/Requests.h"
#include "../CommunicationHandlers/Responses/Responses.h"
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

    // Connection
    bool connect(const std::string& ipAddr, const std::string& password);
    bool disconnected();
    void requestDisconnection();

    // Data exchange
    void updateChannelsData();

    // Accessors
    HCRYPTPROV getAesKey();
    TCPConnection* getTCPConnection();
    std::string getDstIP();
    std::string getLastServerError();

private:
    //===========================//
    //  Networking Connections   //
    //===========================//
    TCPConnection tcpConnection;
    UDPConnection udpScreenConnection;

    //===========================//
    //     Security & Keys       //
    //===========================//
    std::vector<BYTE> serverPublicRsaKey;
    HCRYPTPROV hAESKey;
    HCRYPTPROV hProv;

    //===========================//
    //   Server & Client Info    //
    //===========================//
    std::string ipAddr; // server IP
    std::string lastServerError;
    int serverScreenWidth;
    int serverScreenHeight;
    int clientScreenWidth;
    int clientScreenHeight;
    int colorDepth;
    double qualityScale;

    //===========================//
    //   Connection Lifecycle    //
    //===========================//
    NegotiationState state;
    bool hasDisconnected;
    std::chrono::steady_clock::time_point lastReceivedTime;
    void checkTimeoutThread();

    // Connection negotiation
    bool initiateConnection(const std::string& password);
    void initiateSettingsExchange();

    //===========================//
    //     Input Handling        //
    //===========================//
    void sendInput(Action action);
    static void mouseCallback(int event, int x, int y, int flags, void* userdata);

    //===========================//
    //     Screen Streaming      //
    //===========================//
    void launchScreenshotsThread();
    void receiveScreenshotsThread();
    void showScreenshotImagesThread();
    std::queue<std::vector<uint8_t>> screenshotsQueue;
    std::mutex screenshotQueueMutex;

    //===========================//
    //         Threads           //
    //===========================//
    std::vector<std::thread> threads;

};
