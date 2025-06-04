#include "FileTransfer.h"
#include "../CommunicationHandlers/Codes.h"
#include "../CommunicationHandlers/Requests/Requests.h"
#include "../CommunicationHandlers/Responses/Responses.h"
#include "../CommunicationHandlers/JsonPacketDeserializer.h"
#include "../CommunicationHandlers/JsonPacketSerializer.h"
#include <ShlObj.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <queue>
#include <codecvt>
#include <locale>

FileTransfer::FileTransfer(HCRYPTPROV hAESKey, int srcport, int dstport, Connection* other)
    : tcpConnection(srcport, dstport, MSS, other), hAESKey(hAESKey)
{
    this->transmitting = false;
    this->sendConfirmation = true;
    sendConfirmation = NO_RESPONSE;
}

FileTransfer::~FileTransfer()
{

}

bool FileTransfer::connectionFree()
{
	return !this->transmitting;
}

void FileTransfer::sendFile(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return;
    }

    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    //// Send metadata
    FileTransmissionRequest request;
    request.fileName = filePath.substr(filePath.find_last_of("\\/") + 1);
    request.fileSize = fileSize;
    tcpConnection.sendData(JsonPacketSerializer::serialize(request, this->hAESKey));

    while (sendConfirmation == NO_RESPONSE) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (sendConfirmation == DENIED) {
        sendConfirmation = NO_RESPONSE;
        return;
    }
    sendConfirmation = NO_RESPONSE;
    

    // Send file in chunks
    const size_t CHUNK_SIZE = 1000;
    std::vector<uint8_t> buffer(CHUNK_SIZE);
    size_t totalBytesSent = 0;

    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        std::streamsize bytesRead = file.gcount();
        tcpConnection.sendData(JsonPacketSerializer::serializeFileData(std::vector<uint8_t>(buffer.begin(), buffer.begin() + bytesRead), this->hAESKey));
        totalBytesSent += bytesRead;
        std::cout << "Progress: " << (totalBytesSent * 100 / fileSize) << "%\r" << std::flush;
    }

    file.close();
    std::cout << "File sent successfully!" << std::endl;

}

void FileTransfer::startConnection(const std::string& ipAddress, int entityType)
{
    if (entityType == SERVER) {
        if (tcpConnection.WaitForConnection()) {
            tcpConnection.startReceiving();

        }
    }
    else if (entityType == CLIENT) {
        if (tcpConnection.initializeConnection(ipAddress)) {
            tcpConnection.startReceiving();
        }
    }
    
    std::thread t(&FileTransfer::fileTransmissionRequestResponseListener, this);
    t.detach();
}

void FileTransfer::fileTransmissionRequestResponseListener()
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
            else if (messageCode == (unsigned char)CodeId::FileTransmissionRequest) {
                FileTransmissionRequest fileRequest = JsonPacketDeserializer::deserializeFileTransmissionRequest(receivedData);
                
                FileTransmissionResponse fileTransmissionResponse;
                fileTransmissionResponse.accepted = !this->transmitting;
                
                tcpConnection.sendData(JsonPacketSerializer::serialize(fileTransmissionResponse, this->hAESKey));

                this->transmitting = true;
                std::thread t(&FileTransfer::receiveFileThread, this, fileRequest.fileName, fileRequest.fileSize);
                t.detach();
            }
            else if (messageCode == (unsigned char)CodeId::FileTransmissionResponse) {
                FileTransmissionResponse response = JsonPacketDeserializer::deserializeFileTransmissionResponse(receivedData);
                if (response.accepted) {
                    sendConfirmation = ACCEPTED;
                }
                else {
                    sendConfirmation = DENIED;
                }
            }
            else if (messageCode == (unsigned char)CodeId::FileData) {
                std::vector<uint8_t> responseData = JsonPacketDeserializer::deserializeFileData(receivedData);
                this->fileDataQueue.push(responseData);
            }
        }
    }
}

bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

void FileTransfer::receiveFileThread(std::string receivedFileName, size_t fileSize)
{
    // Get Downloads folder path
    PWSTR downloadsPath = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath);
    if (FAILED(hr)) {
        std::cerr << "Failed to get Downloads folder path." << std::endl;
        return;
    }

    // Convert PWSTR to std::wstring
    std::wstring downloadsFolder(downloadsPath);
    CoTaskMemFree(downloadsPath); // Free memory allocated by SHGetKnownFolderPath

    // Convert receivedFileName to wstring
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wReceivedFileName = converter.from_bytes("remoteControlPC_" + receivedFileName);

    // Construct full path
    std::wstring fullFilePath = downloadsFolder + L"\\" + wReceivedFileName;
    int counter = 1;

    std::wstring wOriginalReceivedFileName = converter.from_bytes(receivedFileName);
    while (FileExists(fullFilePath)) {
        std::wstring newName = L"remoteControlPC_" + std::to_wstring(counter++) + L"-" + wOriginalReceivedFileName;
        fullFilePath = downloadsFolder + L"\\" + newName;
    }

    // Open file in binary mode
    std::ofstream file(fullFilePath, std::ios::binary);
    if (!file.is_open()) {
        std::wcerr << L"Failed to create file: " << fullFilePath << std::endl;
        return;
    }

    // Receive file in chunks
    size_t totalBytesReceived = 0;
    while (totalBytesReceived < fileSize) {
        while (this->fileDataQueue.empty()) {
            continue;
        }

        std::vector<uint8_t> chunk = this->fileDataQueue.front();
        this->fileDataQueue.pop();

        file.write(reinterpret_cast<char*>(chunk.data()), chunk.size());
        totalBytesReceived += chunk.size();
        std::cout << "Progress: " << (totalBytesReceived * 100 / fileSize) << "%\r" << std::flush;
    }

    file.close();
    transmitting = false;

    // Show message box on a separate thread
    std::thread([fullFilePath]() {
        std::wstring msg = L"File received: " + fullFilePath;
        MessageBoxW(NULL, msg.c_str(), L"Transfer Complete", MB_OK | MB_ICONINFORMATION);
    }).detach();
}
