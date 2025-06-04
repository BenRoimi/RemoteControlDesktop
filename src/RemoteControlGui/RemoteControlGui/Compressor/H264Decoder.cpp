#include "H264Decoder.h"
#include <fstream>
#include <sstream>
#include <unordered_map>

H264Decoder::H264Decoder(int width, int height)
    : mContext(nullptr), mPacket(nullptr), mFrame(nullptr), mWidth(width), mHeight(height), mSwsContext(nullptr), mDecodedRGB(nullptr)
{
    const AVCodec* codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec)
    {
        printf("Error: Cannot find decoder.\n");
        exit(1);
    }

    mContext = avcodec_alloc_context3(codec);
    if (!mContext)
    {
        printf("ERROR: Cannot allocate codec context.\n");
        exit(1);
    }

    mPacket = av_packet_alloc();
    mFrame = av_frame_alloc();

    if (avcodec_open2(mContext, codec, nullptr) < 0)
    {
        printf("ERROR: Cannot open codec.\n");
        exit(1);
    }

    mSwsContext = sws_getContext(mWidth, mHeight, AV_PIX_FMT_YUV420P, mWidth, mHeight, AV_PIX_FMT_RGB24, SWS_BILINEAR, nullptr, nullptr, nullptr);

    printf("FFmpeg Decoder is ready.\n");
}

H264Decoder::~H264Decoder()
{
    av_frame_free(&mFrame);
    av_packet_free(&mPacket);
    avcodec_free_context(&mContext);

    if (mSwsContext)
    {
        sws_freeContext(mSwsContext);
    }

    if (mDecodedRGB)
    {
        free(mDecodedRGB);
    }

    printf("End of Decoder program.\n");
}

uint8_t* H264Decoder::decode(uint8_t* iEncodedData, size_t iSize)
{
    if (!iEncodedData)
    {
        return nullptr;
    }

    mPacket->data = iEncodedData;
    mPacket->size = iSize;

    send(mContext, mPacket);
    receive(mContext, mFrame);

    if (mSwsContext)
    {
        if (!mDecodedRGB)
        {
            mDecodedRGB = (uint8_t*)malloc(mWidth * mHeight * 3);
        }

        uint8_t* dst[1] = { mDecodedRGB };
        int dstStride[1] = { mWidth * 3 };
        sws_scale(mSwsContext, mFrame->data, mFrame->linesize, 0, mHeight, dst, dstStride);
    }

    return mDecodedRGB ? mDecodedRGB : mFrame->data[0];
}

void H264Decoder::send(AVCodecContext* iContext, AVPacket* iPacket)
{
    int ret = avcodec_send_packet(iContext, iPacket);
    if (ret < 0)
    {
        printf("Error sending packet: %d\n", ret);
    }
}

void H264Decoder::receive(AVCodecContext* iContext, AVFrame* iFrame)
{
    int ret = avcodec_receive_frame(iContext, iFrame);
    if (ret < 0)
    {
        printf("Error receiving frame: %d\n", ret);
    }
}

int H264Decoder::getDecodedSize()
{
    return mFrame->linesize[0] * mHeight;
}