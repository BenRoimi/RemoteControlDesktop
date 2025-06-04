#pragma once

#include <vector>

extern "C"
{
#include "libavformat/avformat.h"
#include "libavcodec/avcodec.h"
#include "libavutil/opt.h"
#include "libavutil/hwcontext.h"
}

class H264Encoder
{
public:
    H264Encoder(int width, int height);
    ~H264Encoder();

    H264Encoder(H264Encoder& iH264Encoder) = delete;
    void operator=(const H264Encoder& iH264Encoder) = delete;

    uint8_t* encode(uint8_t* iRawData);
    int getPacketSize();

protected:
    void send(AVCodecContext* iContext, AVFrame* iFrame);
    void receive(AVCodecContext* iContext, AVPacket* iPacket);

protected:
    AVCodecContext* mContext;
    AVPacket* mPacket;
    AVFrame* mFrame;
    int mWidth;
    int mHeight;
};