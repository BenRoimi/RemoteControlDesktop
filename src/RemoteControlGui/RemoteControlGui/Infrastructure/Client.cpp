#include "Client.h"
#include <shlwapi.h>
#include <iostream>
#include <memory>
#include <chrono>

#include "../Crypto/Crypto.h"

#pragma comment(lib, "shlwapi.lib")

Client::Client() : tcpConnection(TCPSRCPORT, TCPDSTPORT, MSS), state(NegotiationState::Initial)
{
    if (!CryptAcquireContext(&this->hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << " Error: " << "CryptAcquireContext failed" << GetLastError() << std::endl;
    }
    hasDisconnected = false;
}

bool Client::connect(const std::string& ipAddr, const std::string& password)
{
    hasDisconnected = false;
    if (tcpConnection.initializeConnection(ipAddr)) {
        this->ipAddr = ipAddr;
        udpScreenConnection = UDPConnection(UDPSRCPORTSCREEN, UDPDSTPORTSCREEN, ipAddr, &tcpConnection);
        tcpConnection.startReceiving();

        if (this->initiateConnection(password)) {
            initiateSettingsExchange();

            std::cout << "Negotiation finished, starting data stream" << std::endl;

            launchScreenshotsThread();

            return true;
            
        }
        else {
            while (tcpConnection.getIsConnected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            tcpConnection.stopReceiving();
            tcpConnection.restartConnection();
            return false;
        }
    }
    else {
        lastServerError = "TCP error while trying to connect! please try again later.";
        tcpConnection.restartConnection();
        return false;
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
            else if (messageCode == (unsigned char)CodeId::DissconnectRequest) {
                std::vector<unsigned char> response = JsonPacketSerializer::serializeShortCodeMessage(CodeId::DissconnectResponse);
                tcpConnection.sendData(response);

                MessageBoxA(
                    nullptr,
                    "Server has requested to disconnect. Disconnecting...",
                    "Connection Lost",
                    MB_OK | MB_ICONERROR | MB_TOPMOST
                );

                std::this_thread::sleep_for(std::chrono::seconds(2));
                exit(1);
            }
            else if (JsonPacketDeserializer::getMessageCode(receivedData) == (unsigned char)CodeId::DissconnectResponse) {
                std::cout << "Disconnecting..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(2));
                hasDisconnected = true;
                exit(1);
                break;
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
                this->lastServerError = errorResponse.message;
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

void Client::sendInput(Action action)
{
    std::vector<unsigned char> msg = JsonPacketSerializer::serialize(action, hAESKey);
    tcpConnection.sendData(msg);
}

void Client::receiveScreenshotsThread()
{
    UDPChunksReceiver receiver;
    std::vector<uint8_t> receivedData;
    lastReceivedTime = std::chrono::steady_clock::now();

    while (true) {
        receivedData = udpScreenConnection.receiveData();

        if (!receivedData.empty()) {
            lastReceivedTime = std::chrono::steady_clock::now();
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

void Client::launchScreenshotsThread()
{
    std::thread recieveScreenshotsThread([=]() { receiveScreenshotsThread(); });
    recieveScreenshotsThread.detach();
    std::thread showScreenshotsThread([=]() { showScreenshotImagesThread(); });
    showScreenshotsThread.detach();
    std::thread checkTimeoutThread([=]() { checkTimeoutThread(); });
    checkTimeoutThread.detach();
}

void Client::showScreenshotImagesThread()
{
    auto decoder = std::make_unique<H264Decoder>(serverScreenWidth, serverScreenHeight);
    //uint8_t* encodedData = nullptr;
    int packetSize;
    cv::namedWindow("ServerScreen", cv::WINDOW_NORMAL);
    cv::setMouseCallback("ServerScreen", Client::mouseCallback, this);
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
                
                imshow("ServerScreen", decodedImage);
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
    }
}

void Client::requestDisconnection()
{
    std::vector<unsigned char> request = JsonPacketSerializer::serializeShortCodeMessage(CodeId::DissconnectRequest);
    tcpConnection.sendData(request);
}

bool Client::disconnected()
{
    return this->hasDisconnected;
}

HCRYPTPROV Client::getAesKey()
{
    return this->hAESKey;
}

TCPConnection* Client::getTCPConnection()
{
    return &tcpConnection;
}

std::string Client::getDstIP()
{
    return this->ipAddr;
}

std::string Client::getLastServerError()
{
    return this->lastServerError;
}

void Client::checkTimeoutThread()
{
    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastReceivedTime).count() > 3) {
            MessageBoxA(
                nullptr,
                "Screenshot hasn't been received for 3 seconds. Disconnecting...",
                "Connection Lost",
                MB_OK | MB_ICONERROR | MB_TOPMOST
            );

            std::this_thread::sleep_for(std::chrono::seconds(2));
            exit(1);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

