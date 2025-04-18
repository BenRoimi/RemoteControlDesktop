#include <iostream>
#include "Infrastructure/Server.h"
#include "Infrastructure/Client.h"
#include <fstream>  
#include <vector>
#include <string>
#include <cstdint>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
void sendFile(const std::string& filePath, TCPConnection& tcpConnection);
void receiveFile(TCPConnection& tcpConnection);
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include "Crypto/Crypto.h"
#pragma comment(lib, "advapi32.lib")


//void HandleError(const char* msg) {
//    std::cerr << msg << " Error Code: " << GetLastError() << std::endl;
//    exit(1);
//}
//
//int main() {
//    // Step 1: Acquire a cryptographic context
//    HCRYPTPROV hProv;
//    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
//        HandleError("CryptAcquireContext failed");
//    }
//
//    Crypto crypto;
//
//    // Step 2: Generate RSA Key Pair
//    HCRYPTKEY hRSAKey = crypto.GenerateRSAKey(hProv);
//    if (!hRSAKey) HandleError("Failed to generate RSA key");
//
//    // Step 3: Export RSA Public Key
//    DWORD pubKeySize = 0;
//    CryptExportKey(hRSAKey, 0, PUBLICKEYBLOB, 0, NULL, &pubKeySize);
//    std::vector<BYTE> publicKey(pubKeySize);
//    if (!CryptExportKey(hRSAKey, 0, PUBLICKEYBLOB, 0, publicKey.data(), &pubKeySize)) {
//        HandleError("Failed to export RSA public key");
//    }
//
//    // Simulate sending the RSA public key (this can be sent over a network)
//    std::cout << "RSA Public Key exported and sent." << std::endl;
//
//    // Step 4: Generate AES Key
//    HCRYPTKEY hAESKey = crypto.GenerateAESKey(hProv);
//    if (!hAESKey) HandleError("Failed to generate AES key");
//    printf("HCRYPTPROV hAESKey: %p\n", (void*)hAESKey);
//
//    // Step 5: Encrypt AES Key using RSA Public Key (Received on another system)
//    DWORD aesKeySize = 0;
//    CryptExportKey(hAESKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &aesKeySize);
//    std::vector<BYTE> aesKeyBlob(aesKeySize);
//
//    if (!CryptExportKey(hAESKey, 0, PLAINTEXTKEYBLOB, 0, aesKeyBlob.data(), &aesKeySize)) {
//        HandleError("Failed to export AES key");
//    }
//
//    // Encrypt AES Key using RSA Public Key (Received on another system)
//    std::vector<BYTE> encryptedAESKey;
//    HCRYPTKEY hImportedPubKey;
//    if (!CryptImportKey(hProv, publicKey.data(), publicKey.size(), 0, 0, &hImportedPubKey)) {
//        HandleError("Failed to import RSA public key");
//    }
//    crypto.EncryptRSA(std::string(aesKeyBlob.begin(), aesKeyBlob.end()), encryptedAESKey, hImportedPubKey);
//    CryptDestroyKey(hImportedPubKey);
//
//
//    std::cout << "AES Key encrypted with received RSA Public Key." << std::endl;
//
//    // Simulate receiving the encrypted AES Key and decrypting with RSA Private Key
//    std::string decryptedAESKey;
//    crypto.DecryptRSA(encryptedAESKey, decryptedAESKey, hRSAKey);
//    std::cout << "Decrypted AES Key: " << decryptedAESKey << std::endl;
//
//    // Step 6: Create AES Key from decrypted key material
//    HCRYPTKEY hDecryptedAESKey;
//    if (!CryptImportKey(hProv, (BYTE*)decryptedAESKey.data(), decryptedAESKey.size(), 0, 0, &hDecryptedAESKey)) {
//        HandleError("Failed to import decrypted AES key");
//    }
//    printf("HCRYPTPROV hAESKey Decrypted: %p\n", (void*)hDecryptedAESKey);
//
//    // Step 6: Encrypt Data using AES
//    std::string plaintxt = "Hello, AES Encryption!!";
//    std::vector<BYTE> plaintextBytes(plaintxt.begin(), plaintxt.end()); // Convert string to vector
//    std::vector<BYTE> ciphertxt;
//
//    crypto.EncryptAES(plaintextBytes, ciphertxt, hAESKey);
//
//    std::cout << "Data encrypted with AES." << std::endl;
//
//    // Step 7: Decrypt Data using AES
//    std::vector<BYTE> decryptedBytes;
//    crypto.DecryptAES(ciphertxt, decryptedBytes, hDecryptedAESKey);
//
//    // Convert decrypted vector back to string
//    std::string decryptedTxt(decryptedBytes.begin(), decryptedBytes.end());
//
//    std::cout << "Decrypted Text: " << decryptedTxt << std::endl;
//
//
//    // Cleanup
//    CryptDestroyKey(hRSAKey);
//    CryptDestroyKey(hAESKey);
//    CryptReleaseContext(hProv, 0);
//
//    return 0;
//}

//#include <iostream>
//#include <opencv2/opencv.hpp>
//#include <thread>
//#include <mutex>
//#include <iomanip>
//#include <opencv2/imgproc.hpp>
//#include <opencv2/highgui.hpp>
//
//cv::Mat hwnd2mat(HWND hwnd)
//{
//    HDC hwindowDC, hwindowCompatibleDC;
//
//    int height, width, srcheight, srcwidth;
//    HBITMAP hbwindow;
//    cv::Mat src;
//    BITMAPINFOHEADER  bi;
//
//    hwindowDC = GetDC(hwnd);
//    hwindowCompatibleDC = CreateCompatibleDC(hwindowDC);
//    SetStretchBltMode(hwindowCompatibleDC, COLORONCOLOR);
//
//    RECT windowsize;    // get the height and width of the screen
//    GetClientRect(hwnd, &windowsize);
//
//    srcheight = windowsize.bottom;
//    srcwidth = windowsize.right;
//    height = windowsize.bottom / 1;  //change this to whatever size you want to resize to
//    width = windowsize.right / 1;
//
//    src.create(height, width, CV_8UC3);
//
//    // create a bitmap
//    hbwindow = CreateCompatibleBitmap(hwindowDC, width, height);
//    bi.biSize = sizeof(BITMAPINFOHEADER);    //http://msdn.microsoft.com/en-us/library/windows/window/dd183402%28v=vs.85%29.aspx
//    bi.biWidth = width;
//    bi.biHeight = -height;  //this is the line that makes it draw upside down or not
//    bi.biPlanes = 1;
//    bi.biBitCount = 24;
//    bi.biCompression = BI_RGB;
//    bi.biSizeImage = 0;
//    bi.biXPelsPerMeter = 0;
//    bi.biYPelsPerMeter = 0;
//    bi.biClrUsed = 0;
//    bi.biClrImportant = 0;
//
//    // use the previously created device context with the bitmap
//    SelectObject(hwindowCompatibleDC, hbwindow);
//    // copy from the window device context to the bitmap device context
//    StretchBlt(hwindowCompatibleDC, 0, 0, width, height, hwindowDC, 0, 0, srcwidth, srcheight, SRCCOPY); //change SRCCOPY to NOTSRCCOPY for wacky colors !
//    GetDIBits(hwindowCompatibleDC, hbwindow, 0, height, src.data, (BITMAPINFO*)&bi, DIB_RGB_COLORS);  //copy from hwindowCompatibleDC to hbwindow
//
//    // avoid memory leak
//    DeleteObject(hbwindow);
//    DeleteDC(hwindowCompatibleDC);
//    ReleaseDC(hwnd, hwindowDC);
//
//    return src;
//}
//
//
//// Function to compress the image
//void compressImage(cv::Mat& image, int compression_level)
//{
//    std::vector<uchar> buf;
//    std::vector<int> params;
//    params.push_back(cv::IMWRITE_JPEG_QUALITY);
//    params.push_back(compression_level);
//
//    imencode(".jpg", image, buf, params);
//    image = cv::imdecode(buf, cv::IMREAD_COLOR);
//}
//
//// Function to compress the frame
//void compressFrame(cv::Mat& frame, cv::Mat& compressed_frame, std::mutex& mtx, int compression_level)
//{
//    std::vector<uchar> buf;
//    std::vector<int> params;
//    params.push_back(cv::IMWRITE_JPEG_QUALITY);
//    params.push_back(90);
//
//    while (true)
//    {
//        // Compress the frame
//        cv::Mat local_frame;
//        mtx.lock();
//        frame.copyTo(local_frame);
//        mtx.unlock();
//
//        cv::imencode(".jpg", local_frame, buf, params);
//        mtx.lock();
//        compressed_frame = cv::imdecode(buf, cv::IMREAD_COLOR);
//        mtx.unlock();
//    }
//}
//
//int main()
//{
//    // Prompt user for compression type
//    std::cout << "Enter the compression type (image or video): ";
//    std::string compression_type;
//    std::cin >> compression_type;
//    cv::namedWindow("Compressed Image", cv::WINDOW_NORMAL);
//
//    // Check the compression type
//    if (compression_type == "image")
//    {
//        HWND hwndDesktop = GetDesktopWindow();
//        while (true) {
//            // Read the first frame to get the frame size
//            cv::Mat image = hwnd2mat(hwndDesktop);
//            //// Read the image
//            //cv::Mat image = cv::imread("test.jpg", cv::IMREAD_COLOR);
//            //if (image.empty())
//            //{
//            //    std::cout << "Failed to read image." << std::endl;
//            //    return -1;
//            //}
//
//            //// Prompt user for compression level
//            //std::cout << "Enter the compression level (0-100): ";
//            //int compression_level;
//            //std::cin >> compression_level;
//
//            // Create a copy of the image for compression
//            cv::Mat compressed_image = image.clone();
//
//            // Perform image compression using multithreading
//            compressImage(compressed_image, 90);
//
//            // Calculate the original and compressed image file sizes
//            std::vector<uchar> original_buf, compressed_buf;
//            imencode(".jpg", image, original_buf);
//            imencode(".jpg", compressed_image, compressed_buf);
//            size_t original_size = original_buf.size();
//            size_t compressed_size = compressed_buf.size();
//
//            // Calculate the compression percentage
//            double compression_percentage = 100.0 - (compressed_size / (double)original_size * 100.0);
//
//            // Convert the compression percentage to a string
//            std::stringstream ss;
//            ss << std::fixed << std::setprecision(2) << "Compression: " << compression_percentage << "%";
//            std::string compression_text = ss.str();
//
//            // Display the original and compressed images
//            
//            putText(compressed_image, "Original Size: " + std::to_string(image.cols) + "x" + std::to_string(image.rows), cv::Point(10, 30), cv::FONT_HERSHEY_SIMPLEX, 1, cv::Scalar(255, 255, 255), 2, cv::LINE_AA);
//            putText(compressed_image, "Compressed Size: " + std::to_string(compressed_image.cols) + "x" + std::to_string(compressed_image.rows), cv::Point(10, 70), cv::FONT_HERSHEY_SIMPLEX, 1, cv::Scalar(255, 255, 255), 2, cv::LINE_AA);
//            putText(compressed_image, compression_text, cv::Point(10, 110), cv::FONT_HERSHEY_SIMPLEX, 1, cv::Scalar(255, 255, 255), 2, cv::LINE_AA);
//            imshow("Compressed Image", compressed_image);
//            if (cv::waitKey(1) == 'q')
//                break;
//        }
//        
//    }
//    else if (compression_type == "video")
//    {
//        // Open the webcam for video capture
//        /*cv::VideoCapture cap(0);
//        if (!cap.isOpened())
//        {
//            std::cout << "Failed to open the webcam." << std::endl;
//            return -1;
//        }*/
//        HWND hwndDesktop = GetDesktopWindow();
//
//        // Create a window for the original video
//        cv::namedWindow("Original Video", cv::WINDOW_NORMAL);
//
//        // Create a window for the compressed output video
//        cv::namedWindow("Compressed Output", cv::WINDOW_NORMAL);
//
//        // Mutex for thread synchronization
//        std::mutex mtx;
//
//        // Read the first frame to get the frame size
//        cv::Mat frame = hwnd2mat(hwndDesktop);
//        //cap.read(frame);
//
//        // Create a Mat to hold the compressed frame
//        cv::Mat compressed_frame(frame.size(), CV_8UC3);
//
//        // Prompt user for compression level
//        std::cout << "Enter the compression level (0-100): ";
//        int compression_level;
//        std::cin >> compression_level;
//
//        // Start the compression thread
//        std::thread compression_thread(compressFrame, std::ref(frame), std::ref(compressed_frame), ref(mtx), compression_level);
//
//        // Process frames from the webcam
//        while (true)
//        {
//            frame = hwnd2mat(hwndDesktop);
//
//            // Display the original video
//            imshow("Original Video", frame);
//
//            // Display the compressed output video
//            cv::Mat local_compressed_frame;
//            mtx.lock();
//            compressed_frame.copyTo(local_compressed_frame);
//            mtx.unlock();
//
//            // Calculate the compression percentage
//            std::vector<uchar> compressed_buf;
//            imencode(".jpg", local_compressed_frame, compressed_buf);
//            size_t original_size = frame.total() * frame.elemSize();
//            size_t compressed_size = compressed_buf.size();
//            double compression_percentage = static_cast<double>(compressed_size) / original_size * 1000.0;
//            std::cout << original_size << " " << compressed_size << std::endl;
//
//            // Convert the compression percentage to a string
//            std::stringstream ss;
//            ss << std::fixed << std::setprecision(2) << "Compression: " << compression_percentage << "%";
//            std::string compression_text = ss.str();
//
//            // Display the compressed output video with compression percentage
//            putText(local_compressed_frame, compression_text, cv::Point(10, 30), cv::FONT_HERSHEY_SIMPLEX, 1, cv::Scalar(255, 255, 255), 2, cv::LINE_AA);
//            imshow("Compressed Output", local_compressed_frame);
//
//            // Check for the 'q' key to exit the loop
//            if (cv::waitKey(1) == 'q')
//                break;
//        }
//
//        // Release the VideoCapture object
//        //cap.release();
//
//        // Join the compression thread
//        compression_thread.join();
//    }
//    else
//    {
//        std::cout << "Invalid compression type. Please choose either 'image' or 'video'." << std::endl;
//    }
//
//    // Destroy any OpenCV windows
//    cv::destroyAllWindows();
//
//    return 0;
//}
//#include <opencv2/imgproc.hpp>
//#include <opencv2/highgui.hpp>
//#include <Windows.h>
//#include <iostream>
//#include <opencv2/opencv.hpp>
//#include <cstdint>
//#include <algorithm>
//
//
//// Converts an RGB image to YUV420P format
//void RGBtoYUV420P(const uint8_t* rgb, uint8_t* yuv, int width, int height) {
//    int frameSize = width * height;
//    int uvSize = frameSize / 4; // U and V are quarter the size of Y
//
//    uint8_t* yPlane = yuv;
//    uint8_t* uPlane = yuv + frameSize;
//    uint8_t* vPlane = yuv + frameSize + uvSize;
//
//    // Process each pixel for Y plane
//    for (int j = 0; j < height; j++) {
//        for (int i = 0; i < width; i++) {
//            int rgbIndex = (j * width + i) * 3;
//            uint8_t r = rgb[rgbIndex];
//            uint8_t g = rgb[rgbIndex + 1];
//            uint8_t b = rgb[rgbIndex + 2];
//
//            // Compute Y value
//            yPlane[j * width + i] = static_cast<uint8_t>((0.257 * r + 0.504 * g + 0.098 * b) + 16);
//        }
//    }
//
//    // Process U and V planes with 2x2 subsampling
//    for (int j = 0; j < height; j += 2) {
//        for (int i = 0; i < width; i += 2) {
//            int rgbIndex1 = (j * width + i) * 3;
//            int rgbIndex2 = (j * width + (i + 1)) * 3;
//            int rgbIndex3 = ((j + 1) * width + i) * 3;
//            int rgbIndex4 = ((j + 1) * width + (i + 1)) * 3;
//
//            // Average 2x2 block for U and V components
//            uint8_t r1 = rgb[rgbIndex1], g1 = rgb[rgbIndex1 + 1], b1 = rgb[rgbIndex1 + 2];
//            uint8_t r2 = rgb[rgbIndex2], g2 = rgb[rgbIndex2 + 1], b2 = rgb[rgbIndex2 + 2];
//            uint8_t r3 = rgb[rgbIndex3], g3 = rgb[rgbIndex3 + 1], b3 = rgb[rgbIndex3 + 2];
//            uint8_t r4 = rgb[rgbIndex4], g4 = rgb[rgbIndex4 + 1], b4 = rgb[rgbIndex4 + 2];
//
//            // Compute averaged U and V values
//            uint8_t avg_r = (r1 + r2 + r3 + r4) / 4;
//            uint8_t avg_g = (g1 + g2 + g3 + g4) / 4;
//            uint8_t avg_b = (b1 + b2 + b3 + b4) / 4;
//
//            uPlane[(j / 2) * (width / 2) + (i / 2)] = static_cast<uint8_t>((-0.148 * avg_r - 0.291 * avg_g + 0.439 * avg_b) + 128);
//            vPlane[(j / 2) * (width / 2) + (i / 2)] = static_cast<uint8_t>((0.439 * avg_r - 0.368 * avg_g - 0.071 * avg_b) + 128);
//        }
//    }
//}
//
//void YUV420PtoRGB(const uint8_t* yuv, uint8_t* rgb, int width, int height) {
//    int frameSize = width * height;
//    int uvSize = frameSize / 4; // U and V are quarter the size of Y
//
//    const uint8_t* yPlane = yuv;
//    const uint8_t* uPlane = yuv + frameSize;
//    const uint8_t* vPlane = yuv + frameSize + uvSize;
//
//    for (int j = 0; j < height; j++) {
//        for (int i = 0; i < width; i++) {
//            int yIndex = j * width + i;
//            int uvIndex = (j / 2) * (width / 2) + (i / 2);
//
//            int y = yPlane[yIndex] - 16;
//            int u = uPlane[uvIndex] - 128;
//            int v = vPlane[uvIndex] - 128;
//
//            int r = static_cast<int>(1.164 * y + 1.596 * v);
//            int g = static_cast<int>(1.164 * y - 0.392 * u - 0.813 * v);
//            int b = static_cast<int>(1.164 * y + 2.017 * u);
//
//            if (r < 0) r = 0; if (r > 255) r = 255;
//            if (g < 0) g = 0; if (g > 255) g = 255;
//            if (b < 0) b = 0; if (b > 255) b = 255;
//
//            int rgbIndex = (yIndex * 3);
//            rgb[rgbIndex] = static_cast<uint8_t>(r);
//            rgb[rgbIndex + 1] = static_cast<uint8_t>(g);
//            rgb[rgbIndex + 2] = static_cast<uint8_t>(b);
//        }
//    }
//}
//
//
//
//cv::Mat hwnd2mat(HWND hwnd)
//{
//    HDC hwindowDC, hwindowCompatibleDC;
//
//    int height, width, srcheight, srcwidth;
//    HBITMAP hbwindow;
//    cv::Mat src;
//    BITMAPINFOHEADER  bi;
//
//    hwindowDC = GetDC(hwnd);
//    hwindowCompatibleDC = CreateCompatibleDC(hwindowDC);
//    SetStretchBltMode(hwindowCompatibleDC, COLORONCOLOR);
//
//    RECT windowsize;    // get the height and width of the screen
//    GetClientRect(hwnd, &windowsize);
//
//    srcheight = windowsize.bottom;
//    srcwidth = windowsize.right;
//    height = windowsize.bottom / 1;  //change this to whatever size you want to resize to
//    width = windowsize.right / 1;
//
//    src.create(height, width, CV_8UC3);
//
//    // create a bitmap
//    hbwindow = CreateCompatibleBitmap(hwindowDC, width, height);
//    bi.biSize = sizeof(BITMAPINFOHEADER);    //http://msdn.microsoft.com/en-us/library/windows/window/dd183402%28v=vs.85%29.aspx
//    bi.biWidth = width;
//    bi.biHeight = -height;  //this is the line that makes it draw upside down or not
//    bi.biPlanes = 1;
//    bi.biBitCount = 24;
//    bi.biCompression = BI_RGB;
//    bi.biSizeImage = 0;
//    bi.biXPelsPerMeter = 0;
//    bi.biYPelsPerMeter = 0;
//    bi.biClrUsed = 0;
//    bi.biClrImportant = 0;
//
//    // use the previously created device context with the bitmap
//    SelectObject(hwindowCompatibleDC, hbwindow);
//    // copy from the window device context to the bitmap device context
//    StretchBlt(hwindowCompatibleDC, 0, 0, width, height, hwindowDC, 0, 0, srcwidth, srcheight, SRCCOPY); //change SRCCOPY to NOTSRCCOPY for wacky colors !
//    GetDIBits(hwindowCompatibleDC, hbwindow, 0, height, src.data, (BITMAPINFO*)&bi, DIB_RGB_COLORS);  //copy from hwindowCompatibleDC to hbwindow
//
//    // avoid memory leak
//    DeleteObject(hbwindow);
//    DeleteDC(hwindowCompatibleDC);
//    ReleaseDC(hwnd, hwindowDC);
//
//    return src;
//}
//
//int main()
//{
//    HWND hwndDesktop = GetDesktopWindow();
//    cv::namedWindow("output", cv::WINDOW_NORMAL);
//    int key = 0;
//
//    int width = GetSystemMetrics(SM_CXSCREEN);
//    int height = GetSystemMetrics(SM_CYSCREEN);
//
//    auto encoder = std::make_unique<H264Encoder>(width, height);
//    auto decoder = std::make_unique<H264Decoder>(width, height);
//
//    while (key != 27)
//    {
//        cv::Mat src = hwnd2mat(hwndDesktop);
//        std::vector<uint8_t> yuv(width * height * 3 / 2);
//
//        RGBtoYUV420P(src.data, yuv.data(), width, height);
//
//        // Encode
//        uint8_t* encodedData = encoder->encode(yuv.data());
//        int encodedSize = encoder->getPacketSize();
//
//        std::cout << encodedSize << std::endl; // send between machines
//
//
//        if (encodedData && encodedSize > 0)
//        {
//            // Decode
//            uint8_t* decodedData = decoder->decode(encodedData, encodedSize);
//            //int decodedSize = decoder->getPacketSize();
//
//            
//
//            if (decodedData)
//            {
//                cv::Mat decodedImage(height, width, CV_8UC3);
//                //YUV420PtoRGB(decodedData, decodedImage.data, height, width);
//                decodedImage.data = (uchar*)decodedData;
//
//                imshow("output", decodedImage);
//            }
//        }
//
//        key = cv::waitKey(15); // you can change wait time
//    }
//
//}

int main()
{


    int option;
    std::cout << "1. Connect to server \n2. Create server \nOption: ";
    std::cin >> option;
    if (std::cin.fail()) {
        std::cerr << "Invalid input. Please enter a valid integer." << std::endl;
        return 1;
    }

    if (option == 1) {
        Client client;

        client.connect("192.168.1.133", "123456");
    }
    else if (option == 2) {
        Server server("123456");

        server.WaitForConnection();
        std::cout << "Negotiation finished, starting data stream" << std::endl;

        server.updateChannelData();
    }

    /*Client c1;
    c1.ShowImageWithInput(L"testImg.jpg");*/

    /*Server s1;
    Action moveAction = { ActionType::MouseMove, 400, 300, 0, 0 };
    s1.ExecuteAction(moveAction);*/

    //int option;
    //std::cout << "Enter 1 for sending UDP or 2 for receiving UDP, 3 for sending TCP or 4 for receiving TCP: ";
    //std::cin >> option;

    //if (std::cin.fail()) {
    //    std::cerr << "Invalid input. Please enter a valid integer." << std::endl;
    //    return 1;
    //}

    //if (option == 1) {
    //    UDPConnection udpSender(1234, 4321, "192.168.1.25");
    //    std::vector<uint8_t> data = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
    //    udpSender.sendData(data);
    //    udpSender.closeConnection();
    //}
    //else if (option == 2) {
    //    UDPConnection udpReceiver(4321, 1234);
    //    std::vector<uint8_t> receivedData;
    //    while (true) {
    //        // Receive data (raw bytes)
    //        receivedData = udpReceiver.receiveData();
    //        if (!receivedData.empty()) {
    //            std::cout << "Received data: ";
    //            for (uint8_t byte : receivedData) {
    //                std::cout << std::hex << "0x" << (int)byte << " ";
    //            }
    //            std::cout << std::dec << std::endl;
    //        }
    //    }
    //    udpReceiver.closeConnection();
    //}
    //else if (option == 3) { // Full-duplex TCP sender
    //    TCPConnection tcpConnection(1234, 4321, 6);
    //    if (tcpConnection.initializeConnection("192.168.1.25")) {
    //        tcpConnection.startReceiving();
    //        std::string datastr;
    //        std::cin.ignore();
    //        while (true) {
    //            std::getline(std::cin, datastr);
    //            std::vector<uint8_t> data = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F };
    //            if (datastr == "exit") {
    //                tcpConnection.closeConnection();
    //                break;
    //            }
    //            tcpConnection.sendData(data);
    //        }
    //        tcpConnection.stopReceiving();
    //        
    //    }
    //}
    //else if (option == 4) { // Full-duplex TCP receiver
    //    TCPConnection tcpConnection(4321, 1234, 6);
    //    if (tcpConnection.WaitForConnection()) {
    //        tcpConnection.startReceiving();
    //        std::string datastr;
    //        std::cin.ignore();
    //        while (true) {
    //            std::getline(std::cin, datastr);
    //            std::vector<uint8_t> data = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x6F };
    //            if (datastr == "exit") {
    //                tcpConnection.closeConnection();
    //                break;
    //            }
    //            tcpConnection.sendData(data);
    //        }
    //        tcpConnection.stopReceiving();
    //    }
    //}

    //int option;
    //std::cout << "Enter 1 to send file or 2 to receive file ";
    //std::cin >> option;

    //if (std::cin.fail()) {
    //    std::cerr << "Invalid input. Please enter a valid integer." << std::endl;
    //    return 1;
    //}

    //if (option == 1) { // Full-duplex TCP sender
    //    TCPConnection tcpConnection(1234, 4321, 500);
    //    if (tcpConnection.initializeConnection("192.168.1.25")) {
    //        tcpConnection.startReceiving();
    //        sendFile("D:\\debugging_template.txt", tcpConnection);
    //        tcpConnection.stopReceiving();

    //    }
    //}
    //else if (option == 2) { // Full-duplex TCP receiver
    //    TCPConnection tcpConnection(4321, 1234, 500);
    //    if (tcpConnection.WaitForConnection()) {
    //        tcpConnection.startReceiving();
    //        receiveFile(tcpConnection);
    //        tcpConnection.stopReceiving();
    //    }
    //}
    return 0;
}

void sendFile(const std::string& filePath, TCPConnection& tcpConnection) {
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
    //std::string fileName = filePath.substr(filePath.find_last_of("\\/") + 1);
    //tcpConnection.sendData(std::vector<uint8_t>(fileName.begin(), fileName.end()));

    //std::vector<uint8_t> fileSizeBytes(sizeof(fileSize));
    //std::memcpy(fileSizeBytes.data(), &fileSize, sizeof(fileSize));
    //tcpConnection.sendData(fileSizeBytes);

    // Send file in chunks
    const size_t CHUNK_SIZE = 4096;
    std::vector<uint8_t> buffer(CHUNK_SIZE);
    size_t totalBytesSent = 0;

    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        std::streamsize bytesRead = file.gcount();
        tcpConnection.sendData(std::vector<uint8_t>(buffer.begin(), buffer.begin() + bytesRead));
        totalBytesSent += bytesRead;
        std::cout << "Progress: " << (totalBytesSent * 100 / fileSize) << "%\r" << std::flush;
    }

    file.close();
    std::cout << "File sent successfully!" << std::endl;
}

void receiveFile(TCPConnection& tcpConnection) {

    //// Receive metadata
    //std::vector<uint8_t> fileNameData = tcpConnection.receiveData();
    //std::string fileName(fileNameData.begin(), fileNameData.end());

    //std::vector<uint8_t> fileSizeData = tcpConnection.receiveData();
    //size_t fileSize = *reinterpret_cast<size_t*>(fileSizeData.data());

    // Open file for writing
    std::string fileName = "receivedFile";
    size_t fileSize = 4103;
    std::ofstream file(fileName, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to create file: " << fileName << std::endl;
        return;
    }

    // Receive file in chunks
    const size_t CHUNK_SIZE = 4096;
    size_t totalBytesReceived = 0;

    while (totalBytesReceived < fileSize) {
        while (tcpConnection.isDataEmpty()) {
            continue;
        }
        std::vector<uint8_t> chunk = tcpConnection.getData();
        file.write(reinterpret_cast<char*>(chunk.data()), chunk.size());
        totalBytesReceived += chunk.size();
        std::cout << "Progress: " << (totalBytesReceived * 100 / fileSize) << "%\r" << std::flush;
    }

    file.close();
    std::cout << "File received successfully!" << std::endl;
}

