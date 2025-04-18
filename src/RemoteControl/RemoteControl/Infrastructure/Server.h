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
#include "../ConnectionHelpers/UDPChunksTransfer.h"
#include "../Compressor/H264Encoder.h"
#include <windows.h>
#include <mmsystem.h>
#include <atomic>
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/opencv.hpp>

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

    void WaitForConnection();
    void selectMonitior();
    void updateChannelData();

private:
    HCRYPTPROV hAESKey;
    HCRYPTPROV hRSAKey;
    HCRYPTPROV hProv;

    TCPConnection tcpConnection;
    UDPConnection udpScreenConnection;
    UDPConnection udpAudioConnection;
    std::string pass;
    NegotiationState state;
    VirtualChannelManager channelManager;
    std::string ipAddr;
    bool hasExited;

    // Monitor selection
    std::vector<MonitorInfo> availableMonitors;
    MonitorInfo selectedMonitor;
    std::atomic<bool> capturing{ false };
    int colorDepth;
    double qualityScale; // 0 - 1.0

    bool handleConnectionInitialization();
    void denyAccessAndRestart();
    void handleSettingsExchange(const std::vector<unsigned int> channelsToRemove);
    void ExecuteAction(const Action& action);
    void exitInputThread();

    void captureScreenshot(const HDC hScreenDC, const HDC hMemoryDC, const HBITMAP hBitmap, const int screenWidth, const int screenHeight, std::vector<unsigned char>& buffer);
    void startCaptureLoop(const int frameRate);
    void startCapture(const int frameRate);
    void stopCapture();
    void startRecording();

    // new functions:

    cv::Mat hwnd2mat(HWND hwnd);
    void RGBtoYUV420P(const uint8_t* rgb, uint8_t* yuv, int width, int height);
};
