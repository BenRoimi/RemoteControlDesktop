#pragma once

#include <vector>
extern "C"
{
#include "libavformat/avformat.h"
#include "libavcodec/avcodec.h"
#include "libavutil/opt.h"
#include "libavutil/hwcontext.h"
#include "libswscale/swscale.h"  // For converting YUV420P to RGB (optional)
}

class H264Decoder
{
public:
    H264Decoder(int width, int height);
    ~H264Decoder();

    H264Decoder(H264Decoder& iH264Decoder) = delete;
    void operator=(const H264Decoder& iH264Decoder) = delete;

    uint8_t* decode(uint8_t* iEncodedData, size_t iSize);
    int getDecodedSize();

protected:
    void send(AVCodecContext* iContext, AVPacket* iPacket);
    void receive(AVCodecContext* iContext, AVFrame* iFrame);

protected:
    AVCodecContext* mContext;
    AVPacket* mPacket;
    AVFrame* mFrame;
    int mWidth;
    int mHeight;
    SwsContext* mSwsContext;  // For format conversion (optional)
    uint8_t* mDecodedRGB;  // Output RGB data (optional)
};