#include "VirtualChannelManager.h"
#include <iostream>
#include <thread>

VirtualChannelManager::VirtualChannelManager()
{
    initializeDefaultChannels();
}

const std::vector<VirtualChannel>& VirtualChannelManager::getChannels() const
{
    return channels;
}

void VirtualChannelManager::initializeDefaultChannels()
{
    channels.push_back({ "Global", 1, true });    // ערוץ גלובלי להודעות כלליות
    channels.push_back({ "ScreenSharing", 2, false });   // ערוץ לשיתוף מסך
    channels.push_back({ "InputEvents", 3, true });     // ערוץ לאירועי קלט
    channels.push_back({ "Audio", 4, true });    // ערוץ לשמע
    channels.push_back({ "FileTransfer", 5, true });    // ערוץ להעברת קבצים
    channels.push_back({ "Heartbeat", 6, false });     // ערוץ לבדיקת פעילות החיבור
}

void VirtualChannelManager::removeNotWantedChannels(const std::vector<unsigned int> channelsToRemove)
{
    channels.erase(
        std::remove_if(
            channels.begin(),
            channels.end(),
            [&channelsToRemove](const VirtualChannel& channel) {
                // Check if the channel ID is in channelsToRemove
                return std::find(channelsToRemove.begin(), channelsToRemove.end(), channel.channelId) != channelsToRemove.end();
            }
        ),
        channels.end()
    );
}

void VirtualChannelManager::createAllChannelsThreads()
{
    for (const auto& channel : channels) {
        std::cout << "Creating channel thread: " << channel.name
            << " (ID: " << channel.channelId
            << ", Reliable: " << (channel.reliable ? "Yes" : "No") << ")\n";

        std::thread thread(&VirtualChannelManager::virtualChannelsThread, this, std::ref(channel));
        thread.detach();
    }
}

void VirtualChannelManager::virtualChannelsThread(VirtualChannel virtualChannel)
{
    while (true) {

    }
    // add communication for each virtual channel (or create a new method for each channel thread)
    // if needed - pass the connection of tcp/udp or save the connections in THIS class variables
    // and remove the connections from the main classes (Server + Client) because all the communication
    // will be happening in the virtual channels

    // can push the messages to the VirtualChannel's msgsQueue
    // and a thread from the main classes (Server + Client) will read from the queue
}
