#include "Server.h"
//#include <mmdeviceapi.h>
//#include <audioclient.h>
#include "../Crypto/Crypto.h"

Server::Server(std::string password) : tcpConnection(TCPSRCPORT, TCPDSTPORT, MSS), pass(password),
state(NegotiationState::Initial)
{
    colorDepth = 24;
    qualityScale = 0.5;
    // currently, for easier communication

    if (!CryptAcquireContext(&this->hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << " Error: " << "CryptAcquireContext failed" << GetLastError() << std::endl;
    }

}

void Server::WaitForConnection()
{
    // ask the user what channels are not wanted (show only the neccessery ones)
    //"InputEvents", 3
    //"Audio", 4
    //"FileTransfer", 5 f
    std::vector<unsigned int> channelsToRemove; // example for tests
    channelsToRemove.push_back(4);
    channelsToRemove.push_back(5);

    while (true) {
        if (tcpConnection.WaitForConnection()) {
            this->ipAddr = tcpConnection.getDestIp();
            udpScreenConnection = UDPConnection(UDPSRCPORTSCREEN, UDPDSTPORTSCREEN, ipAddr, &tcpConnection);
            udpAudioConnection = UDPConnection(UDPSRCPORTAUDIO, UDPDSTPORTAUDIO, ipAddr, &tcpConnection);
            tcpConnection.startReceiving();

            while (true) {
                if (!tcpConnection.isDataEmpty()) {
                    if (this->handleConnectionInitialization()) {
                        channelManager.removeNotWantedChannels(channelsToRemove);
                        handleSettingsExchange(channelsToRemove);
                        channelManager.createAllChannelsThreads();
                        break;
                    }
                    else {
                        tcpConnection.stopReceiving();
                        break;
                    }
                }
            }

            startCapture(FPS);
            std::cout << "Started screenshot capturing" << std::endl;
            /*std::thread audioThread([=]() { startRecording(); });
            audioThread.detach();*/

            break;
        }
    }
}

// Global vector to temporarily store monitors during enumeration
std::vector<MonitorInfo> monitorsTemp;

BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) {
    MONITORINFOEX monitorInfo;
    monitorInfo.cbSize = sizeof(MONITORINFOEX);

    if (GetMonitorInfo(hMonitor, &monitorInfo)) {
        MonitorInfo info;

        std::wstring wsname(monitorInfo.szDevice);
        std::string namestr(wsname.begin(), wsname.end());
        info.name = namestr; // Convert name to std::string
        info.width = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
        info.height = monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top;
        info.x = monitorInfo.rcMonitor.left;
        info.y = monitorInfo.rcMonitor.top;

        monitorsTemp.push_back(info); // Add monitor to the temp list
    }

    return TRUE; // Continue enumeration
}

void Server::selectMonitior()
{
    monitorsTemp.clear(); // Clear the temporary list
    if (!EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, 0)) {
        std::cerr << "Failed to enumerate monitors." << std::endl;
        return;
    }
    availableMonitors = monitorsTemp;

    if (availableMonitors.size() == 1) {
        selectedMonitor = availableMonitors[0];
    }
    else {
        // Display available monitors in a numbered list
        std::cout << "Available Monitors:" << std::endl;
        int index = 1;
        for (const MonitorInfo& monitor : availableMonitors) {
            std::cout << index++ << ". " << monitor.name << "   "
                << monitor.width << " x " << monitor.height << std::endl;
        }

        // Prompt the user to select a monitor
        int choice = -1;
        std::cout << "Enter the number of the monitor to select: ";
        std::cin >> choice;

        // Validate the user input
        if (choice > 0 && choice <= static_cast<int>(availableMonitors.size())) {
            selectedMonitor = availableMonitors[choice - 1];
            std::cout << "Selected Monitor: " << selectedMonitor.name
                << "  Resolution: " << selectedMonitor.width
                << "x" << selectedMonitor.height
                << "  Position: (" << selectedMonitor.x << ", " << selectedMonitor.y << ")" << std::endl;
        }
        else {
            std::cerr << "Invalid selection. Please try again." << std::endl;
        }
    }
}

void Server::updateChannelData()
{
    while (true) {
        if (!tcpConnection.isDataEmpty()) {
            std::vector<unsigned char> receivedData;
            try {
                receivedData = JsonPacketDeserializer::getFullMessageFromTcpConnectionStream(tcpConnection, hAESKey);
            }
            catch (const std::runtime_error& e) {
                // Catch and handle std::runtime_error specifically
                std::cerr << "Caught runtime_error: " << e.what() << std::endl;
                continue;
            }
            catch (const std::exception& e) {
                // Catch other std::exception types
                std::cerr << "Caught exception: " << e.what() << std::endl;
                continue;
            }
            catch (...) {
                // Catch all other exceptions
                std::cerr << "Caught an unknown exception!" << std::endl;
                continue;
            }
            unsigned char messageCode = receivedData[4];

            // Here move the data to the right channel
            if (messageCode == (unsigned char)CodeId::Error) {
                ErrorResponse errorResponse = JsonPacketDeserializer::deserializeErrorResponse(receivedData);
                std::cout << "Connection denied, server responded: " << errorResponse.message << std::endl;
            }
            else if (messageCode == (unsigned char)CodeId::SendAction) {
                Action action = JsonPacketDeserializer::deserializeActionResponse(receivedData);
                ExecuteAction(action);
            }
            else if (messageCode == (unsigned char)CodeId::DissconnectRequest) {
                std::vector<unsigned char> response = JsonPacketSerializer::serializeShortCodeMessage(CodeId::DissconnectResponse);
                tcpConnection.sendData(response);

                std::cout << "Requested to disconnect. Disconnecting..." << std::endl;

                hasExited = true;
            }
            else {
                std::string str(receivedData.begin(), receivedData.end());
                std::cout << "strange data detected  " << receivedData[4] << std::endl <<  str << std::endl;
            }
        }
    }
}

bool Server::handleConnectionInitialization()
{
    ConnectionInitiationRequest connectionInitiationRequest;
    try {
        connectionInitiationRequest = JsonPacketDeserializer::deserializeConnectionRequest(JsonPacketDeserializer::getFullMessageFromTcpConnectionStream(tcpConnection));
    }
    catch (const std::runtime_error& e) {
        // Catch and handle std::runtime_error specifically
        std::cerr << "Caught runtime_error: " << e.what() << std::endl;
        return false;
    }
    catch (const std::exception& e) {
        // Catch other std::exception types
        std::cerr << "Caught exception: " << e.what() << std::endl;
        return false;
    }
    catch (...) {
        // Catch all other exceptions
        std::cerr << "Caught an unknown exception!" << std::endl;
        return false;
    }

    if (connectionInitiationRequest.password != this->pass) {
        std::cout << "Client tried to connect with wrong password!" << std::endl;

        this->denyAccessAndRestart();
        return false;
    }

    // Ask the User if he likes the connection, if not, return objection
    std::cout << "User with ip " << tcpConnection.getDestIp() << " tried to connect, enter 1 for accepting: ";
    int option;
    std::cin >> option;

    if (option == 1) {
        AesKeyRequest aesKeyRequest;

        // Generate RSA Key Pair
        this->hRSAKey = Crypto::GenerateRSAKey(hProv);
        if (!hRSAKey) {
            std::cerr << "GenerateRSAKey failed" << " Error: " << GetLastError() << std::endl;
        }

        // Export RSA Public Key
        DWORD pubKeySize = 0;
        CryptExportKey(hRSAKey, 0, PUBLICKEYBLOB, 0, NULL, &pubKeySize);
        std::vector<BYTE> publicKey(pubKeySize);
        if (!CryptExportKey(hRSAKey, 0, PUBLICKEYBLOB, 0, publicKey.data(), &pubKeySize)) {
            std::cerr << "Failed to export RSA public key" << " Error: " << GetLastError() << std::endl;
        }

        // print - remove after dubug
        for (BYTE b : publicKey) {
            std::cout << "rsa: " << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        }
        std::cout << std::dec << std::endl; // Reset to decimal format

        aesKeyRequest.publicRsaKey = publicKey;

        std::vector<unsigned char> aesKeyRequestBuffer = JsonPacketSerializer::serialize(aesKeyRequest);

        tcpConnection.sendData(aesKeyRequestBuffer);

        // wait for aes key
        std::vector<unsigned char> receivedData;
        while (true) {
            if (!tcpConnection.isDataEmpty()) {
                try {
                    receivedData = JsonPacketDeserializer::getFullMessageFromTcpConnectionStream(tcpConnection);
                    break;
                }
                catch (const std::runtime_error& e) {
                    // Catch and handle std::runtime_error specifically
                    std::cerr << "Caught runtime_error: " << e.what() << std::endl;
                    continue;
                }
                catch (const std::exception& e) {
                    // Catch other std::exception types
                    std::cerr << "Caught exception: " << e.what() << std::endl;
                    continue;
                }
                catch (...) {
                    // Catch all other exceptions
                    std::cerr << "Caught an unknown exception!" << std::endl;
                    continue;
                }
            }
        }

        AesKeyResponse aesKeyResponse = JsonPacketDeserializer::deserializeAesKeyResponse(receivedData);

        std::string decryptedAESKey;
        Crypto::DecryptRSA(aesKeyResponse.aesKey, decryptedAESKey, hRSAKey);
        std::cout << "Decrypted AES Key: " << decryptedAESKey << std::endl;

        if (!CryptImportKey(hProv, (BYTE*)decryptedAESKey.data(), decryptedAESKey.size(), 0, 0, &this->hAESKey)) {
            std::cerr << "Failed to import decrypted AES key" << " Error: " << GetLastError() << std::endl;
        }
        printf("HCRYPTPROV hAESKey: %p\n", (void*)hAESKey);

        return true;
    }
    else {
        this->denyAccessAndRestart();
        return false;
    }
}

void Server::denyAccessAndRestart()
{
    // Return objection
    ErrorResponse errorResponse;
    errorResponse.message = "Access to server denied!";

    std::vector<unsigned char> response = JsonPacketSerializer::serialize(errorResponse, hAESKey);
    tcpConnection.sendData(response);

    // Restart the tcp connection
    tcpConnection.closeConnection();
}

void Server::handleSettingsExchange(const std::vector<unsigned int> channelsToRemove) {
    // wait for get settings request
    while (true) {
        if (!tcpConnection.isDataEmpty()) {
            selectMonitior();

            // Serialize the request into a vector of bytes
            SettingsExchangeResponse response;
            response.screenHeight = selectedMonitor.height;
            response.screenWidth = selectedMonitor.width;
            // HDC hdc = GetDC(nullptr);
            // response.colorDepth = GetDeviceCaps(hdc, BITSPIXEL);
            response.colorDepth = this->colorDepth; // set at the constructor
            response.qualityScale = this->qualityScale; // set at the constructor
            response.virtualChannelsToRemove = channelsToRemove;

            std::cout << "Sending settings exchange response..." << std::endl;
            std::vector<unsigned char> serializedResponse = JsonPacketSerializer::serialize(response, hAESKey);
            tcpConnection.sendData(serializedResponse);
            break;
        }
    }
}

void Server::ExecuteAction(const Action& action)
{
    switch (action.type) {
    case ActionType::MouseMove:
        SetCursorPos(selectedMonitor.x + action.x, selectedMonitor.y + action.y);
        std::cout << "MouseMove: x = " << selectedMonitor.x + action.x << ", y = " << selectedMonitor.y + action.y << std::endl;
        break;

    case ActionType::MouseClick: {
        INPUT input = {};
        input.type = INPUT_MOUSE;
        if (action.button == MouseAction::LeftMouseDown) {
            input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
            SetCursorPos(selectedMonitor.x + action.x, selectedMonitor.y + action.y);
            std::cout << "MouseClick: button = LeftMouseDown" << std::endl;
        }
        else if (action.button == MouseAction::LeftMouseUp) {
            input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
            SetCursorPos(selectedMonitor.x + action.x, selectedMonitor.y + action.y);
            std::cout << "MouseClick: button = LeftMouseUp" << std::endl;
        }
        else if (action.button == MouseAction::RightMouseDown) {
            input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
            SetCursorPos(selectedMonitor.x + action.x, selectedMonitor.y + action.y);
            std::cout << "MouseClick: button = RightMouseDown" << std::endl;
        }
        else if (action.button == MouseAction::RightMouseUp) {
            input.mi.dwFlags = MOUSEEVENTF_RIGHTUP;
            SetCursorPos(selectedMonitor.x + action.x, selectedMonitor.y + action.y);
            std::cout << "MouseClick: button = RightMouseUp" << std::endl;
        }
        SendInput(1, &input, sizeof(INPUT));
        break;
    }

    case ActionType::KeyPress: {
        INPUT input = {};
        input.type = INPUT_KEYBOARD;
        input.ki.wVk = VkKeyScanA(action.key);
        if (input.ki.wVk == -1) {
            std::cerr << "Invalid key: " << action.key << std::endl;
            break;
        }
        SendInput(1, &input, sizeof(INPUT));

        // Release the key
        input.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &input, sizeof(INPUT));
        std::cout << "KeyPress: key = " << action.key << " (" << static_cast<int>(action.key) << ")" << std::endl;
        break;
    }

    default:
        std::cerr << "Unknown action type received.\n";
        break;
    }
}

void Server::exitInputThread()
{
    //while (true) {
    //    std::string input;
    //    std::getline(std::cin, input);

    //    if (input == "exit") break;
    //}
    // 
    // just for checks
    std::this_thread::sleep_for(std::chrono::seconds(10));

    std::vector<unsigned char> request = JsonPacketSerializer::serializeShortCodeMessage(CodeId::DissconnectRequest);
    tcpConnection.sendData(request);

    std::cout << "sent req" << std::endl;

    while (true) {
        if (!tcpConnection.isDataEmpty()) {
            std::vector<unsigned char> receivedData;
            try {
                receivedData = JsonPacketDeserializer::getFullMessageFromTcpConnectionStream(tcpConnection, hAESKey);
            }
            catch (const std::runtime_error& e) {
                // Catch and handle std::runtime_error specifically
                std::cerr << "Caught runtime_error: " << e.what() << std::endl;
                break;
            }
            catch (const std::exception& e) {
                // Catch other std::exception types
                std::cerr << "Caught exception: " << e.what() << std::endl;
                break;
            }
            catch (...) {
                // Catch all other exceptions
                std::cerr << "Caught an unknown exception!" << std::endl;
                break;
            }


            if (JsonPacketDeserializer::getMessageCode(receivedData) == (unsigned char)CodeId::DissconnectResponse) {
                std::cout << "Disconnecting..." << std::endl;
                break;
            }
        }
    }

    hasExited = true;
}

void Server::captureScreenshot(const HDC hScreenDC, const HDC hMemoryDC, const HBITMAP hBitmap,
    const int screenWidth, const int screenHeight,
    std::vector<unsigned char>& buffer)
{
    int colorBitDepth = 24; // Set to 24-bit (RGB)

    // Allocate memory for BITMAPINFOHEADER
    std::vector<unsigned char> bitmapInfo(sizeof(BITMAPINFOHEADER));

    // Set up BITMAPINFOHEADER
    BITMAPINFO* bi = reinterpret_cast<BITMAPINFO*>(bitmapInfo.data());
    bi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi->bmiHeader.biWidth = screenWidth;
    bi->bmiHeader.biHeight = -screenHeight; // Negative to avoid flipping
    bi->bmiHeader.biPlanes = 1;
    bi->bmiHeader.biBitCount = colorBitDepth;
    bi->bmiHeader.biCompression = BI_RGB;
    bi->bmiHeader.biSizeImage = 0;
    bi->bmiHeader.biXPelsPerMeter = 0;
    bi->bmiHeader.biYPelsPerMeter = 0;
    bi->bmiHeader.biClrUsed = 0;
    bi->bmiHeader.biClrImportant = 0;

    // Copy the screen content to the bitmap
    BitBlt(hMemoryDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY);

    // Calculate the required buffer size
    size_t bytesPerPixel = colorBitDepth / 8;
    size_t rowSize = ((screenWidth * bytesPerPixel + 3) & ~3); // Ensure row size is DWORD-aligned
    size_t bufferSize = rowSize * screenHeight;
    buffer.resize(bufferSize); // Resize the buffer to fit the image data

    // Retrieve the bitmap bits
    int result = GetDIBits(hMemoryDC, hBitmap, 0, screenHeight, buffer.data(), bi, DIB_RGB_COLORS);
    if (result == 0) {
        DWORD error = GetLastError();
        std::cerr << "GetDIBits failed with error: " << error << std::endl;
    }
}


void Server::startCaptureLoop(const int frameRate)
{
    // int key = 0;
    int width = selectedMonitor.width;
    int height = selectedMonitor.height;

    auto encoder = std::make_unique<H264Encoder>(width, height);
    UDPChunksTransfer imageTransfer(&udpScreenConnection);

    std::thread exitThread([=]() { exitInputThread(); });
    exitThread.detach();

    std::this_thread::sleep_for(std::chrono::seconds(4));

    // while (key != 27)
    while (true)
    {
        cv::Mat src = hwnd2mat(GetDesktopWindow()); // thr func does not literaly mean the desktop monitor
        std::vector<uint8_t> yuv(width * height * 3 / 2);

        RGBtoYUV420P(src.data, yuv.data(), width, height);

        // Encode
        uint8_t* encodedData = encoder->encode(yuv.data());
        int encodedSize = encoder->getPacketSize();

        std::cout << encodedSize << std::endl; 

        std::vector<uint8_t> encodedVector(encodedData, encodedData + encodedSize);
        imageTransfer.sendEncryptedData(encodedVector, hAESKey);

        // key = cv::waitKey(10);

        if (hasExited) {
            break;
        }
    }

    //HWND hwndDesktop = GetDesktopWindow();

    //cv::Mat frame = hwnd2mat(hwndDesktop);

    // Create a Mat to hold the compressed frame
    //cv::Mat compressed_frame(frame.size(), CV_8UC3);



    //imageTransfer.sendData(encodedVector);
    //// Compressor
    //uint8_t* wEncodedData = nullptr;
    //auto encoder = std::make_unique<H264Encoder>(GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));

    //// change it to work with the selected monitor (currentlt not) line down
    //// Get screen dimensions
    //int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    //int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    //// Allocate buffer for raw bitmap data
    //int dataSize = ((screenWidth * 24 + 31) / 32) * 4 * screenHeight;
    //std::vector<unsigned char> buffer(dataSize);

    //// Create reusable resources
    //HDC hScreenDC = GetDC(nullptr);
    //HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    //HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
    //HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);

    //// Frame interval
    //auto frameInterval = std::chrono::milliseconds(1000 / frameRate);

    //UDPChunksTransfer imageTransfer(&udpScreenConnection);
    //bool success;

    //// Capture loop
    //while (capturing.load()) {
    //    int wPacketSize = 0;
    //    auto start = std::chrono::steady_clock::now();
    //    success = false;

    //    captureScreenshot(hScreenDC, hMemoryDC, hBitmap, screenWidth, screenHeight, buffer);

    //    wEncodedData = encoder->encode(buffer.data());

    //    if (nullptr != wEncodedData)
    //    {
    //        wPacketSize = encoder->getPacketSize();
    //    }

    //    // Convert to vector
    //    std::vector<uint8_t> encodedVector(wEncodedData, wEncodedData + wPacketSize);

    //    std::cout << "Commpressed size: " << encodedVector.size() << "; Old size: " << buffer.size() << " bytes\n";
    //    success = imageTransfer.sendData(encodedVector);
    //    if (success) {
    //        std::cout << "Successfully sent screenshot - " << encodedVector.size() << " bytes\n";
    //    }
    //    else {
    //        std::cout << "Fail to send screenshot\n";
    //    }

    //    // Ensure consistent frame rate
    //    std::this_thread::sleep_until(start + frameInterval);
    //}

    //// Cleanup resources
    //SelectObject(hMemoryDC, hOldBitmap);
    //DeleteObject(hBitmap);
    //DeleteDC(hMemoryDC);
    //ReleaseDC(nullptr, hScreenDC);
}

void Server::startCapture(const int frameRate)
{
    capturing.store(true);
    std::thread captureThread([=]() { startCaptureLoop(frameRate); });
    captureThread.detach();
}

void Server::stopCapture()
{
    capturing.store(false);
}

// later, can also change this function to use different levels of compression using another parameter in compress()
//std::vector<uint8_t> Server::compressImage(const std::vector<uint8_t>& image)
//{
//    uLongf compressedSize = compressBound(image.size());
//    std::vector<uint8_t> compressedData(compressedSize);
//
//    if (compress(compressedData.data(), &compressedSize, image.data(), image.size()) != Z_OK) {
//        throw std::runtime_error("Compression failed");
//    }
//
//    compressedData.resize(compressedSize); // resize to actual compressed size
//    return compressedData;
//}

void Server::startRecording()
{
    //HRESULT hr;
    //CoInitialize(nullptr);

    //// Get the default audio device (system playback)
    //IMMDeviceEnumerator* deviceEnumerator = nullptr;
    //hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&deviceEnumerator);
    //IMMDevice* device = nullptr;
    //hr = deviceEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &device);

    //// Activate audio client
    //IAudioClient* audioClient = nullptr;
    //hr = device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&audioClient);

    //// Get format and initialize audio client
    //WAVEFORMATEX* waveFormat;
    //hr = audioClient->GetMixFormat(&waveFormat);
    //hr = audioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, 10000000, 0, waveFormat, nullptr);

    //// Get the capture client
    //IAudioCaptureClient* captureClient = nullptr;
    //hr = audioClient->GetService(__uuidof(IAudioCaptureClient), (void**)&captureClient);

    //UDPChunksTransfer audioTransfer(&udpAudioConnection);

    //audioClient->Start(); // Start capturing audio
    //std::cout << "Recording started...\n";

    //std::cout << "Sample Rate: " << waveFormat->nSamplesPerSec << " Hz, "
    //    << "Channels: " << waveFormat->nChannels << ", "
    //    << "Bits per Sample: " << waveFormat->wBitsPerSample << " bits, "
    //    << "Block Align: " << waveFormat->nBlockAlign << " bytes, "
    //    << "Average Bytes per Second: " << waveFormat->nAvgBytesPerSec << " bytes/sec" << std::endl;

    //while (true) {
    //    UINT32 packetLength = 0;
    //    captureClient->GetNextPacketSize(&packetLength);
    //    while (packetLength > 0) {
    //        BYTE* data;
    //        UINT32 framesAvailable;
    //        DWORD flags;
    //        captureClient->GetBuffer(&data, &framesAvailable, &flags, nullptr, nullptr);
    //        std::cout << "Frames per buffer: " << framesAvailable << std::endl;

    //        std::vector<unsigned char> dataVector(data, data + framesAvailable * waveFormat->nBlockAlign);
    //        audioTransfer.sendData(dataVector);

    //        captureClient->ReleaseBuffer(framesAvailable);
    //        captureClient->GetNextPacketSize(&packetLength);
    //    }
    //}

    //// Cleanup
    //udpAudioConnection.closeConnection();
    //WSACleanup();
    //captureClient->Release();
    //audioClient->Release();
    //device->Release();
    //deviceEnumerator->Release();
    //CoUninitialize();
}

cv::Mat Server::hwnd2mat(HWND hwnd)
{
    HDC hwindowDC, hwindowCompatibleDC;
    int height, width, srcheight, srcwidth;
    HBITMAP hBitmap;
    cv::Mat src;
    BITMAPINFOHEADER bi;

    hwindowDC = GetDC(hwnd);
    hwindowCompatibleDC = CreateCompatibleDC(hwindowDC);
    SetStretchBltMode(hwindowCompatibleDC, COLORONCOLOR);

    srcheight = selectedMonitor.height;
    srcwidth = selectedMonitor.width;
    height = srcheight / 1;  //change this to whatever size you want to resize to
    width = srcwidth / 1;

    src.create(height, width, CV_8UC3);

    // create a bitmap
    hBitmap = CreateCompatibleBitmap(hwindowDC, width, height);
    bi.biSize = sizeof(BITMAPINFOHEADER);    //http://msdn.microsoft.com/en-us/library/windows/window/dd183402%28v=vs.85%29.aspx
    bi.biWidth = width;
    bi.biHeight = -height;  //this is the line that makes it draw upside down or not
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    // use the previously created device context with the bitmap
    SelectObject(hwindowCompatibleDC, hBitmap);
    // copy from the window device context to the bitmap device context

    //StretchBlt(hwindowCompatibleDC, 0, 0, width, height, hwindowDC, 0, 0, srcwidth, srcheight, SRCCOPY); //change SRCCOPY to NOTSRCCOPY for wacky colors !

    BitBlt(hwindowCompatibleDC, 0, 0, width, height, hwindowDC, selectedMonitor.x, selectedMonitor.y, SRCCOPY);
    GetDIBits(hwindowCompatibleDC, hBitmap, 0, height, src.data, (BITMAPINFO*)&bi, DIB_RGB_COLORS);  //copy from hwindowCompatibleDC to hbwindow

    // avoid memory leak
    DeleteObject(hBitmap);
    DeleteDC(hwindowCompatibleDC);
    ReleaseDC(hwnd, hwindowDC);

    return src;
}

void Server::RGBtoYUV420P(const uint8_t* rgb, uint8_t* yuv, int width, int height)
{
    int frameSize = width * height;
    int uvSize = frameSize / 4; // U and V are quarter the size of Y

    uint8_t* yPlane = yuv;
    uint8_t* uPlane = yuv + frameSize;
    uint8_t* vPlane = yuv + frameSize + uvSize;

    // Process each pixel for Y plane
    for (int j = 0; j < height; j++) {
        for (int i = 0; i < width; i++) {
            int rgbIndex = (j * width + i) * 3;
            uint8_t r = rgb[rgbIndex];
            uint8_t g = rgb[rgbIndex + 1];
            uint8_t b = rgb[rgbIndex + 2];

            // Compute Y value
            yPlane[j * width + i] = static_cast<uint8_t>((0.257 * r + 0.504 * g + 0.098 * b) + 16);
        }
    }

    // Process U and V planes with 2x2 subsampling
    for (int j = 0; j < height; j += 2) {
        for (int i = 0; i < width; i += 2) {
            int rgbIndex1 = (j * width + i) * 3;
            int rgbIndex2 = (j * width + (i + 1)) * 3;
            int rgbIndex3 = ((j + 1) * width + i) * 3;
            int rgbIndex4 = ((j + 1) * width + (i + 1)) * 3;

            // Average 2x2 block for U and V components
            uint8_t r1 = rgb[rgbIndex1], g1 = rgb[rgbIndex1 + 1], b1 = rgb[rgbIndex1 + 2];
            uint8_t r2 = rgb[rgbIndex2], g2 = rgb[rgbIndex2 + 1], b2 = rgb[rgbIndex2 + 2];
            uint8_t r3 = rgb[rgbIndex3], g3 = rgb[rgbIndex3 + 1], b3 = rgb[rgbIndex3 + 2];
            uint8_t r4 = rgb[rgbIndex4], g4 = rgb[rgbIndex4 + 1], b4 = rgb[rgbIndex4 + 2];

            // Compute averaged U and V values
            uint8_t avg_r = (r1 + r2 + r3 + r4) / 4;
            uint8_t avg_g = (g1 + g2 + g3 + g4) / 4;
            uint8_t avg_b = (b1 + b2 + b3 + b4) / 4;

            uPlane[(j / 2) * (width / 2) + (i / 2)] = static_cast<uint8_t>((-0.148 * avg_r - 0.291 * avg_g + 0.439 * avg_b) + 128);
            vPlane[(j / 2) * (width / 2) + (i / 2)] = static_cast<uint8_t>((0.439 * avg_r - 0.368 * avg_g - 0.071 * avg_b) + 128);
        }
    }
}