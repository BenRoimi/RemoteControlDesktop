#pragma once
#include "../Connection/TCPConnection.h"
#define NO_RESPONSE 0
#define DENIED 1
#define ACCEPTED 2

#define MSS 1460
#define FILETRANSFERCLIENTTCPSRCPORT 5000
#define FILETRANSFERTCPCLIENTDSTPORT 5001
#define FILETRANSFERUDPSERVERSRCPORT 5001
#define FILETRANSFERTCPSERVERDSTPORT 5000

#define SERVER 1
#define CLIENT 2

class FileTransfer
{
public:
	FileTransfer(HCRYPTPROV hAESKey, int srcport, int dstport, Connection* other);
	~FileTransfer();
	bool connectionFree();
	void sendFile(const std::string& filePath);

	void startConnection(const std::string& ipAddress, int entityType);
private:
	TCPConnection tcpConnection;

	void fileTransmissionRequestResponseListener();
	void receiveFileThread(std::string receivedFileName, size_t fileSize);

	bool transmitting;
	int sendConfirmation;
	HCRYPTPROV hAESKey;

	std::queue<std::vector<uint8_t>> fileDataQueue;
};

