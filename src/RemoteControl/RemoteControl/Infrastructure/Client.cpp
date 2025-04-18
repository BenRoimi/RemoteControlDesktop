#include "Client.h"
#include <shlwapi.h>
#include <iostream>
#include <memory>
#include <opencv2/opencv.hpp>
#include "../Crypto/Crypto.h"
//#include <portaudio.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "portaudio.lib")

Client::Client() : tcpConnection(TCPSRCPORT, TCPDSTPORT, MSS), state(NegotiationState::Initial)
{
    if (!CryptAcquireContext(&this->hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << " Error: " << "CryptAcquireContext failed" << GetLastError() << std::endl;
    }
}

bool Client::connect(const std::string& ipAddr, const std::string& password)
{
    if (tcpConnection.initializeConnection(ipAddr)) {
        this->ipAddr = ipAddr;
        udpScreenConnection = UDPConnection(UDPSRCPORTSCREEN, UDPDSTPORTSCREEN, ipAddr, &tcpConnection);
        udpAudioConnection = UDPConnection(UDPSRCPORTAUDIO, UDPDSTPORTAUDIO, ipAddr, &tcpConnection);
        tcpConnection.startReceiving();

        if (this->initiateConnection(password)) {
            initiateSettingsExchange();

            std::cout << "Negotiation finished, starting data stream" << std::endl;

            lunchScreenshotsThread();
            //std::thread audioThread([=]() { startReceivingAudio(); });
            //audioThread.detach();

            updateChannelsData();
        }
        else {
            while (tcpConnection.getIsConnected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            tcpConnection.stopReceiving();
            return false;
        }
    }
}

void Client::updateChannelsData()
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
            
            // Repond according to the data
            if (messageCode == (unsigned char)CodeId::Error) {
                ErrorResponse errorResponse = JsonPacketDeserializer::deserializeErrorResponse(receivedData);
                std::cout << "Connection denied, server responded: " << errorResponse.message << std::endl;
            }
            else if(messageCode == (unsigned char)CodeId::DissconnectRequest) {
                std::vector<unsigned char> response = JsonPacketSerializer::serializeShortCodeMessage(CodeId::DissconnectResponse);
                tcpConnection.sendData(response);

                std::cout << "Requested to disconnect. Disconnecting..." << std::endl;

                hasExited = true;
            }
            else {

            }
        }
    }
}

bool Client::initiateConnection(const std::string& password)
{
    ConnectionInitiationRequest connectionRequest;
    connectionRequest.password = password;
    std::vector<unsigned char> connectionRequestbuffer = JsonPacketSerializer::serialize(connectionRequest);
    tcpConnection.sendData(connectionRequestbuffer);

    while (true) {
        if (!tcpConnection.isDataEmpty()) {
            std::vector<unsigned char> receivedBuffer;
            try {
                receivedBuffer = JsonPacketDeserializer::getFullMessageFromTcpConnectionStream(tcpConnection);
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
            unsigned char messageCode = receivedBuffer[4];

            if (messageCode == (unsigned char)CodeId::Error) {
                ErrorResponse errorResponse = JsonPacketDeserializer::deserializeErrorResponse(receivedBuffer);
                std::cout << "Connection denied, server responded: " << errorResponse.message << std::endl;
                return false;
            }
            else if (messageCode == (unsigned char)CodeId::AesKeyRequest) {

                std::cout << "Connection accepted, moving to next stage." << std::endl;

                AesKeyRequest AesKeyRequest = JsonPacketDeserializer::deserializeAesKeyRequest(receivedBuffer);

                this->serverPublicRsaKey = AesKeyRequest.publicRsaKey; // get public rsa key

                // print - remove after dubug
                for (BYTE b : serverPublicRsaKey) {
                    std::cout << "rsa: " << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
                }
                std::cout << std::dec << std::endl; // Reset to decimal format

                // Generate AES Key
                this->hAESKey = Crypto::GenerateAESKey(this->hProv);
                if (!hAESKey) {
                    std::cerr << "Failed to generate AES key" << " Error: " << GetLastError() << std::endl;
                }

                // Encrypt AES Key using RSA Public Key (Received on another system)
                DWORD aesKeySize = 0;
                CryptExportKey(hAESKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &aesKeySize);
                std::vector<BYTE> aesKeyBlob(aesKeySize);

                if (!CryptExportKey(hAESKey, 0, PLAINTEXTKEYBLOB, 0, aesKeyBlob.data(), &aesKeySize)) {
                    std::cerr << "Failed to export AES key" << " Error: " << GetLastError() << std::endl;
                }

                std::vector<BYTE> encryptedAESKey;
                HCRYPTKEY hImportedPubKey;
                if (!CryptImportKey(hProv, serverPublicRsaKey.data(), serverPublicRsaKey.size(), 0, 0, &hImportedPubKey)) {
                    std::cerr << "Failed to import RSA public key" << " Error: " << GetLastError() << std::endl;
                }
                Crypto::EncryptRSA(std::string(aesKeyBlob.begin(), aesKeyBlob.end()), encryptedAESKey, hImportedPubKey);
                CryptDestroyKey(hImportedPubKey);

                // print for debug - can be deleted!
                printf("HCRYPTPROV hAESKey: %p\n", (void*)hAESKey);

                // send rsa key 
                AesKeyResponse aesKeyResponse;
                aesKeyResponse.aesKey = encryptedAESKey;

                std::vector<unsigned char> aesKeyResponseBuffer = JsonPacketSerializer::serialize(aesKeyResponse);

                tcpConnection.sendData(aesKeyResponseBuffer);

                // wait for 2 seconds
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                return true;
            }
            else {
                std::cout << "Error occurred, try again later." << std::endl;
                return false;
            }
        }
    }
}

void Client::initiateSettingsExchange() {
    // Initiate setting  SettingsExchangeRequest
    std::vector<unsigned char> request = JsonPacketSerializer::serializeShortCodeMessage(CodeId::SettingsExchangeRequest, hAESKey);
    tcpConnection.sendData(request);

    // receive settings from the server
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
            SettingsExchangeResponse response = JsonPacketDeserializer::deserializeSettingsResponse(receivedData);
            serverScreenWidth = response.screenWidth;
            serverScreenHeight = response.screenHeight;
            colorDepth = response.colorDepth;
            qualityScale = response.qualityScale;

            std::cout << "Server width: " << serverScreenWidth << " height: " << serverScreenHeight << std::endl;
            break;
        }
    }
}

void Client::mouseCallback(int event, int x, int y, int flags, void* userdata) {
    Client* self = static_cast<Client*>(userdata);

    Action action;
    static std::chrono::steady_clock::time_point lastMouseMoveTime = std::chrono::steady_clock::now();

    if (event == cv::EVENT_MOUSEMOVE) {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastMouseMoveTime);
        
        if (elapsed.count() < 250) { // less than 250ms - skip
            return;
        }
        lastMouseMoveTime = currentTime; // Update the time

        std::cout << "Mouse Position: (" << x << ", " << y << ")" << std::endl;
        action.type = ActionType::MouseMove;
        action.x = x;
        action.y = y;
        self->sendInput(action);
    }
    else if (event == cv::EVENT_LBUTTONDOWN) {
        std::cout << "Left Button Pressed at: (" << x << ", " << y << ")" << std::endl;
        action.type = ActionType::MouseClick;
        action.button = MouseAction::LeftMouseDown;
        action.x = x;
        action.y = y;
        self->sendInput(action);
    }
    else if (event == cv::EVENT_LBUTTONUP) {
        std::cout << "Left Button Released at: (" << x << ", " << y << ")" << std::endl;
        action.type = ActionType::MouseClick;
        action.button = MouseAction::LeftMouseUp;
        action.x = x;
        action.y = y;
        self->sendInput(action);
    }
    else if (event == cv::EVENT_RBUTTONDOWN) {
        std::cout << "Right Button Pressed at: (" << x << ", " << y << ")" << std::endl;
        action.type = ActionType::MouseClick;
        action.button = MouseAction::RightMouseDown;
        action.x = x;
        action.y = y;
        self->sendInput(action);
    }
    else if (event == cv::EVENT_RBUTTONUP) {
        std::cout << "Right Button Released at: (" << x << ", " << y << ")" << std::endl;
        action.type = ActionType::MouseClick;
        action.button = MouseAction::RightMouseUp;
        action.x = x;
        action.y = y;
        self->sendInput(action);
    }
}

void Client::exitInputThread()
{
    while (true) {
        std::string input;
        std::getline(std::cin, input);

        if (input == "exit") break;
    }

    std::vector<unsigned char> request = JsonPacketSerializer::serializeShortCodeMessage(CodeId::DissconnectRequest);
    tcpConnection.sendData(request);
    
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

//void Client::HandleInput(UINT msg, WPARAM wParam, LPARAM lParam) {
//    // function sends input to the server
//    Action action;
//    static std::chrono::steady_clock::time_point lastMouseMoveTime = std::chrono::steady_clock::now();
//
//    switch (msg) {
//    case WM_MOUSEMOVE:
//    {
//        auto currentTime = std::chrono::steady_clock::now();
//        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastMouseMoveTime);
//
//        if (elapsed.count() < 100) { // less than 100ms - skip
//            break;
//        }
//        lastMouseMoveTime = currentTime; // Update the time
//
//        int x = LOWORD(lParam);
//        int y = HIWORD(lParam);
//        std::cout << "Mouse moved to: (" << x << ", " << y << ")\n";
//        action.type = ActionType::MouseMove;
//        action.x = x;
//        action.y = y;
//        sendInput(action);
//        break;
//    }
//    case WM_LBUTTONDOWN:
//    {
//        int x = LOWORD(lParam);
//        int y = HIWORD(lParam);
//        std::cout << "Left mouse button clicked in(" << x << ", " << y << ")\n";
//        action.type = ActionType::MouseClick;
//        action.button = 'L';
//        action.x = x;
//        action.y = y;
//        sendInput(action);
//        break;
//    }
//    case WM_RBUTTONDOWN:
//    {
//        int x = LOWORD(lParam);
//        int y = HIWORD(lParam);
//        std::cout << "Right mouse button clicked in(" << x << ", " << y << ")\n";
//        action.type = ActionType::MouseClick;
//        action.button = 'R';
//        action.x = x;
//        action.y = y;
//        sendInput(action);
//        break;
//    }
//    case WM_KEYDOWN:
//        std::cout << "Key pressed: " << static_cast<char>(wParam) << "\n";
//        action.type = ActionType::KeyPress;
//        action.key = static_cast<char>(wParam);
//        sendInput(action);
//        break;
//    default:
//        break;
//    }
//}

void Client::sendInput(Action action)
{
    std::vector<unsigned char> msg = JsonPacketSerializer::serialize(action, hAESKey);
    tcpConnection.sendData(msg);
}

void Client::recieveScreenshotsThread()
{
    UDPChunksReceiver receiver;
    std::vector<uint8_t> receivedData;

    while (true) {
        receivedData = udpScreenConnection.receiveData();

        if (!receivedData.empty()) {
            receiver.handlePacket(receivedData);

            if (receiver.isComplete()) {
                std::vector<uint8_t> reconstructedImage = receiver.reconstructAndDecryptData(hAESKey);
                // processing the reconstructed image
                receiver.resetHandling();

                std::cout << "Recieved screenshot - " << reconstructedImage.size() << " bytes." << std::endl;

                std::unique_lock<std::mutex> lock(screenshotQueueMutex);
                screenshotsQueue.push(reconstructedImage);
                lock.unlock();
            }
        }
    }
}

void Client::lunchScreenshotsThread()
{
    std::thread recieveScreenshotsThread([=]() { recieveScreenshotsThread(); });
    recieveScreenshotsThread.detach();
    std::thread showScreenshotsThread([=]() { showScreenshotImagesThread(); });
    showScreenshotsThread.detach();
}

void Client::showScreenshotImagesThread()
{
    auto decoder = std::make_unique<H264Decoder>(serverScreenWidth, serverScreenHeight);
    //uint8_t* encodedData = nullptr;
    int packetSize;
    cv::namedWindow("output", cv::WINDOW_NORMAL);
    cv::setMouseCallback("output", Client::mouseCallback, this);
    int count = 0;

    while (true) 
    {
        if (!screenshotsQueue.empty()) {
            count++;
            
            int wPacketSize = 0;
            std::unique_lock<std::mutex> lock(screenshotQueueMutex);
            packetSize = screenshotsQueue.front().size();
            std::vector<uint8_t> encodedData = screenshotsQueue.front();
            screenshotsQueue.pop();
            lock.unlock();

            uint8_t* decodedData = decoder->decode(encodedData.data(), packetSize);

            if (decodedData)
            {
                cv::Mat decodedImage(serverScreenHeight, serverScreenWidth, CV_8UC3);
                decodedImage.data = (uchar*)decodedData;

                //saveImage(decodedImage, "example.jpg");
                
                imshow("output", decodedImage);
                cv::waitKey(1);
            }
        }

        // dont move to function, has to be in the main loop
        int key = cv::waitKey(10);
        if (key != -1) { // -1 means no key was pressed
            char chKey = key;
            Action action;
            action.type = ActionType::KeyPress;
            action.key = chKey;
            std::cout << "Key pressed: " << chKey << "\n";
            sendInput(action);
        }

        if (hasExited) {
            break;
        }
    }
}


void Client::startReceivingAudio()
{
    //UDPChunksReceiver receiver;
    //std::vector<uint8_t> audioData;
    //// while (true){} // this is for debugging other things, remove!

    //PaStream* stream;
    //PaStreamParameters outputParameters;

    //// Initialize PortAudio
    //PaError err = Pa_Initialize();
    //if (err != paNoError) {
    //    std::cerr << "PortAudio initialization failed: " << Pa_GetErrorText(err) << std::endl;
    //    return;
    //}

    //outputParameters.device = Pa_GetDefaultOutputDevice();
    //if (outputParameters.device == paNoDevice) {
    //    std::cerr << "Error: No default output device." << std::endl;
    //    return;
    //}

    //outputParameters.channelCount = 2; // Stereo output
    //outputParameters.sampleFormat = paFloat32; // Ensure your data is float
    //outputParameters.suggestedLatency = Pa_GetDeviceInfo(outputParameters.device)->defaultLowOutputLatency;
    //outputParameters.hostApiSpecificStreamInfo = NULL;

    //// Open the stream for **output**
    //err = Pa_OpenStream(&stream, NULL, &outputParameters, SAMPLE_RATE, FRAMES_PER_BUFFER, paClipOff, NULL, NULL);
    //if (err != paNoError) {
    //    std::cerr << "PortAudio open stream failed: " << Pa_GetErrorText(err) << std::endl;
    //    return;
    //}

    //// Start the stream before writing
    //err = Pa_StartStream(stream);
    //if (err != paNoError) {
    //    std::cerr << "PortAudio start stream failed: " << Pa_GetErrorText(err) << std::endl;
    //    return;
    //}

    //while (true) {
    //    audioData = udpAudioConnection.receiveData();

    //    if (!audioData.empty()) {
    //        receiver.handlePacket(audioData);

    //        if (receiver.isComplete()) {
    //            std::vector<uint8_t> reconstructedAudio = receiver.reconstructData();
    //            receiver.resetHandling();

    //            // Convert audio data (assuming float 32-bit stereo, 44.1kHz)
    //            // Convert buffer to float data
    //            std::vector<float> audioBuffer(reconstructedAudio.size() / sizeof(float));
    //            std::memcpy(audioBuffer.data(), reconstructedAudio.data(), reconstructedAudio.size());

    //            float* audioData = audioBuffer.data();
    //            // Play audio
    //            err = Pa_WriteStream(stream, audioData, audioBuffer.size() / 2); // Stereo
    //            if (err != paNoError) {
    //                std::cerr << "PortAudio write stream failed: " << Pa_GetErrorText(err) << std::endl;
    //                break;
    //            }

    //            std::cout << "Received " << reconstructedAudio.size() << " bytes of audio" << std::endl;
    //        }
    //    }
    //}

    //// Cleanup
    //udpAudioConnection.closeConnection();
    //Pa_StopStream(stream);
    //Pa_CloseStream(stream);
    //Pa_Terminate();
    //WSACleanup();
}
