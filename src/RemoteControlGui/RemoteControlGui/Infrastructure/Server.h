#pragma once
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/opencv.hpp>

#include <string>
#include "../Connection/TCPConnection.h"
#include "../Connection/UDPConnection.h"
#include "../CommunicationHandlers/Codes.h"
#include "../CommunicationHandlers/Requests/Requests.h"
#include "../CommunicationHandlers/Responses/Responses.h"
#include "../CommunicationHandlers/JsonPacketDeserializer.h"
#include "../CommunicationHandlers/JsonPacketSerializer.h"
#include "../ConnectionHelpers/UDPChunksTransfer.h"
#include "../Compressor/H264Encoder.h"
#include <windows.h>
#include <mmsystem.h>
#include <atomic>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

#define MSS 1460
#define TCPSRCPORT 1234
#define TCPDSTPORT 4321
#define UDPSRCPORTSCREEN 5678
#define UDPDSTPORTSCREEN 8765
#define UDPSRCPORTAUDIO 5666
#define UDPDSTPORTAUDIO 8777

#define FPS 5

#define SAMPLE_RATE 44100 // 44.1kHz
#define NUM_CHANNELS 1 // mono audio - single channel, all sounds are mixed together
#define BITS_PER_SAMPLE 16 // 8-bit - lower quality, 16-bit - standard CD quality, 24-bit - very high quality
#define BUFFER_SIZE 4096  // for 100 ms of 16-bit mono audio at 44.1kHz
#define NUM_BUFFERS 3  // Use multiple buffers for smooth recording
// #define SAMPLES_PER_BUFFER 1024
#define SAMPLES_PER_BUFFER 8820 / (BITS_PER_SAMPLE / 8)

class Server {
public:
    Server(std::string password);

    //===========//
    // Lifecycle //
    //===========//
    bool WaitForConnection();
    void AcceptConenction();
    void denyAccess(std::string error);
    void restartTCPData();
    void requestDisconnection();

    //===========//
    // Channels  //
    //===========//
    void updateChannelData();
    void handleSettingsExchange(const std::vector<unsigned int> channelsToRemove);
    void startCapture(const int frameRate);

    //===========//
    // Monitor   //
    //===========//
    void setMonitor(MonitorInfo monitor);

    //===========//
    // Getters   //
    //===========//
    std::string getSrcIP();
    std::string getDstIP();
    std::string getPass();
    HCRYPTPROV getAesKey();
    TCPConnection* getTCPConnection();

private:
    //==================================//
    //    Security & Encryption Keys    //
    //==================================//
    HCRYPTPROV hAESKey;
    HCRYPTPROV hRSAKey;
    HCRYPTPROV hProv;

    //===============================//
    //  Networking & Communication   //
    //===============================//
    TCPConnection tcpConnection;
    UDPConnection udpScreenConnection;

    NegotiationState state;
    std::string ipAddr;
    std::string pass;
    bool hasDisconnected;
    int AcceptedConnection;

    //===============================//
    //     Monitor & Capture Info    //
    //===============================//
    MonitorInfo selectedMonitor;
    std::atomic<bool> capturing{ false };
    int colorDepth;
    double qualityScale;

    //===============================//
    //       Internal Logic          //
    //===============================//
    bool handleConnectionInitialization();
    void ExecuteAction(const Action& action);

    //===============================//
    //    Screenshot Capture Logic   //
    //===============================//
    void captureScreenshot(const HDC hScreenDC, const HDC hMemoryDC, const HBITMAP hBitmap, const int screenWidth, const int screenHeight, std::vector<unsigned char>& buffer);
    void startCaptureLoop(const int frameRate);
    void stopCapture();
    void startRecording();

    //===============================//
    //       Utility Functions       //
    //===============================//
    cv::Mat hwnd2mat(HWND hwnd);
    void RGBtoYUV420P(const uint8_t* rgb, uint8_t* yuv, int width, int height);    

};
