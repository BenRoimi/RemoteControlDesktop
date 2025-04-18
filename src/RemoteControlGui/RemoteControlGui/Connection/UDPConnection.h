#pragma once
#include "Connection.h"
#include "NetworkHeaders_Structures.h"
#include <vector>

class UDPConnection : public Connection
{
public:
    UDPConnection();
    UDPConnection(int srcPort, int dstPort);
    UDPConnection(int srcPort, int dstPort, const std::string& ipaddress);
    UDPConnection(int srcPort, int dstPort, Connection* other);
    UDPConnection(int srcPort, int dstPort, const std::string& ipaddress, Connection* other);
    void closeConnection();
    bool sendData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> receiveData();
    unsigned short calculateChecksum(unsigned short* buffer, size_t size);

private:
    int srcPort;
    int dstPort;
    std::string ipAddress;
};

