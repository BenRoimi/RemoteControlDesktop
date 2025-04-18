#pragma once
#include <string>
#include <vector>
#include <queue>

struct VirtualChannel {
    std::string name;
    int channelId;
    bool reliable;
    std::queue<unsigned char> msgsQueue;
};

class VirtualChannelManager {
public:
    VirtualChannelManager();

    const std::vector<VirtualChannel>& getChannels() const;
    void removeNotWantedChannels(const std::vector<unsigned int> channelsToRemove);
    void createAllChannelsThreads();

private:
    std::vector<VirtualChannel> channels;

    void initializeDefaultChannels();
    void virtualChannelsThread(VirtualChannel virtualChannel);

    // here create funciton for each thread
};
