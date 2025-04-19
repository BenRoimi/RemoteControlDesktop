# 🖥️ Remote Control Desktop – P2P Screen Sharing

A peer-to-peer remote desktop system built in C++ that allows one machine to view and control another machine’s screen in real time.

This project focuses on communication using custom protocol design, screen capture optimization, low-level network programming, and secured data.

---

## ✨ Features

- 📺 **Real-time screen sharing** at moderate frame rates
- 🧠 **Peer-to-peer (P2P)** architecture – no central server
- 📡 **Raw socket communication** (TCP or UDP) with custom protocol
- 🖱️ **Remote mouse and keyboard control**
- 🧮 **Network traffic optimization** - H264 compression
- 🔐 Encryption and authentication modules (has to enter a password in order to connect)

---

## 🔧 Tech Stack

- **C++**
- **NPcap, custom packets**
- **Keyboard control using WinAPI**
- **Mouse control and screen display using OpenCV**
- **Multithreading**
- **Compression**

---
Important!

- In order to run the program with the libraries I used, you must download them from their official website, and place it in the folder outside of the program itself.
- wxWidgets - https://www.wxwidgets.org/downloads , call the folder "wxWidgets"
- openCV - https://opencv.org/releases , call the folder "opencvBuild"

