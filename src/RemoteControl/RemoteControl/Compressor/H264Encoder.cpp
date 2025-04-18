#include "H264Encoder.h"
#include <iostream>

H264Encoder::H264Encoder(int width, int height)
    : mContext(nullptr), mPacket(nullptr), mFrame(nullptr), mWidth(width), mHeight(height)
{
    const AVCodec* codec = avcodec_find_encoder_by_name("libx264");
    if (!codec)
    {
        printf("Error: Cannot find encoder.\n");
        exit(1);
    }

    mContext = avcodec_alloc_context3(codec);
    if (!mContext)
    {
        printf("ERROR: Cannot start codec context.\n");
        exit(1);
    }

    mContext->bit_rate = 2000000;
    mContext->width = mWidth;
    mContext->height = mHeight;
    mContext->time_base = { 1, 25 };
    mContext->gop_size = 10;
    mContext->max_b_frames = 0;
    mContext->pix_fmt = AV_PIX_FMT_YUV420P;

    av_opt_set(mContext->priv_data, "preset", "ultrafast", 0);
    av_opt_set(mContext->priv_data, "tune", "zerolatency", 0);
    av_opt_set(mContext->priv_data, "crf", "28", 0);

    if (avcodec_open2(mContext, codec, nullptr) < 0)
    {
        printf("ERROR: Cannot open codec.\n");
        exit(1);
    }

    mPacket = av_packet_alloc();
    mFrame = av_frame_alloc();
    mFrame->format = mContext->pix_fmt;
    mFrame->width = mContext->width;
    mFrame->height = mContext->height;

    if (av_frame_get_buffer(mFrame, 32) < 0)
    {
        printf("ERROR: Cannot allocate frame buffer.\n");
        exit(1);
    }
}

H264Encoder::~H264Encoder()
{
    av_frame_free(&mFrame);
    avcodec_free_context(&mContext);
    av_packet_free(&mPacket);
}

uint8_t* H264Encoder::encode(uint8_t* iRawData)
{
    if (!iRawData) return nullptr;

    int ySize = mWidth * mHeight;
    int uvSize = ySize / 4;

    memcpy(mFrame->data[0], iRawData, ySize);
    memcpy(mFrame->data[1], iRawData + ySize, uvSize);
    memcpy(mFrame->data[2], iRawData + ySize + uvSize, uvSize);

    send(mContext, mFrame);
    receive(mContext, mPacket);

    return mPacket->data;
}

int H264Encoder::getPacketSize()
{
    return mPacket->data ? mPacket->size : 0;
}

void H264Encoder::send(AVCodecContext* iContext, AVFrame* iFrame)
{
    if (avcodec_send_frame(iContext, iFrame) < 0)
    {
        printf("Error sending frame.\n");
    }
}

void H264Encoder::receive(AVCodecContext* iContext, AVPacket* iPacket)
{
    if (avcodec_receive_packet(iContext, iPacket) < 0)
    {
        printf("Error receiving packet.\n");
    }
}
