# 🖥️ Remote Control Desktop – P2P Screen Sharing

A peer-to-peer remote desktop system built in C++ that allows one machine to view and control another machine’s screen in real time.

This project focuses on high-performance transmission using custom protocol design, screen capture optimization, and low-level network programming.

---

## ✨ Features

- 📺 **Real-time screen sharing** at high frame rates
- 🧠 **Peer-to-peer (P2P)** architecture – no central server
- 📡 **Raw socket communication** (TCP or UDP) with custom protocol
- 🖱️ **Remote mouse and keyboard control**
- 🧮 **Network traffic optimization** (e.g., simulated congestion window – CWND)
- 🔐 Potential for future encryption and authentication modules

---

## 🔧 Tech Stack

- **C++**
- **Raw Sockets / WinSock / BSD sockets**
- **Screen capture APIs** (e.g., GDI, X11, or cross-platform libs like OpenCV or SFML)
- **Multithreading** for responsive streaming
- **Compression** for screen data

---
Important!

In order to run the program with the libraries I used, you must download them from their official website, and place it in the folder outside of the program itself.
wxWidgets - https://www.wxwidgets.org/downloads , call the folder "wxWidgets"
openCV - https://opencv.org/releases , call the folder "opencvBuild"

