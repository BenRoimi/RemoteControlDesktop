# 🖥️ Remote Control PC

![35](https://github.com/user-attachments/assets/03c50b7b-b15e-430a-8c8b-f4ba1e8f1283)
![36](https://github.com/user-attachments/assets/b736f7e7-a3b6-4543-9451-ee8c8b1e8d1b)
![120](https://github.com/user-attachments/assets/b4089c96-3744-46bf-b9e0-80395d3e355a)

## 🚀 Overview

**Remote Control PC** is a full-stack remote control system written in **C++**, enabling users to securely connect and control a remote computer in real time. It features:
- Live screen streaming (H.264 encoding)
- Real-time mouse & keyboard synchronization
- Secure file transfer between server and client
- Custom low-level implementation of TCP/UDP/ARP protocols
- End-to-end hybrid encryption using RSA and AES

---

## 🧠 Project Goals

- Create a lightweight, fast, and secure remote control system.
- Learn and implement low-level networking based on OSI layers without using high-level libraries.
- Provide a usable tool for remote technical support, server management, and file access.

---

## 🔧 Key Features

| Feature | Description |
|--------|-------------|
| **Live Screen Sharing** | Real-time video stream from server to client using H.264 |
| **Remote Input** | Sends mouse movements, keyboard input and clicks securely |
| **File Transfer** | Two-way encrypted file sharing |
| **Custom Encryption** | RSA key exchange, AES session encryption |
| **Protocol Control** | Manual packet handling (TCP, UDP, ARP) using raw sockets |

---

## 🧱 System Architecture

### Client:
- GUI built with **wxWidgets**
- Receives and displays live screen stream (OpenCV)
- Captures local input and sends to server
- Sends/receives files with AES encryption

### Server:
- Runs background listener for connections
- Captures and encodes screen (WinAPI + FFmpeg)
- Emulates remote input using **WinAPI**
- Handles secure file I/O

---

## 🔐 Security

- **RSA 2048-bit key exchange**
- **AES-128 encryption** for ongoing communication
- Authentication: Password-protected sessions
- No third-party servers – direct, private communication
- MITM-resilient by secure handshake and encrypted key delivery

---

## 📚 Technologies Used

| Technology | Purpose |
|------------|---------|
| `C++` | Core logic and custom protocols |
| `Npcap` | Raw packet capture and sending |
| `wxWidgets` | GUI for both server and client |
| `FFmpeg` | Real-time screen encoding (H.264) |
| `OpenCV` | Frame decoding & screen rendering |
| `WinAPI` | Input capture, screen access, file dialogs |

---

## 🧪 Testing Highlights

- Invalid IP → shows error
- Wrong/empty password → blocked access
- File overwrite warning if file already exists
- File sending errors handled with alerts
- Manual disconnects gracefully terminate session

---

## 📈 Why This Project?

This project was built from scratch with minimal reliance on external libraries in order to:
- Deepen technical knowledge of **networks, encryption, and protocols**
- Simulate real-world challenges in **remote access software**
- Create a fully operational, practical product useful in everyday tech support

---

 ## How to run the exe file

 ### Download the latest version of OpenCV from their website - https://opencv.org/releases

 ![105](https://github.com/user-attachments/assets/8eb70b6a-8511-4099-832a-1e1b3be4291b)
During installation, proceed with the default settings

### Prepare Required DLL Files

Download all the required DLL files from the GitHub repository under:
RemoteControlDesktop/ffmpeg-7.1/dep/

Copy all files from full_build-shared/bin into:
C:\Windows\System32

Next, copy all .dll files from the following OpenCV folder:
opencv/build/x64/vc16/bin/
into:
C:\Windows\System32

### Download and install Npcap from their website - https://npcap.com

![110](https://github.com/user-attachments/assets/f93407f8-b8c1-4074-bb5d-57fbea7625cf)
During installation, select all default options

### Done! Now you can download the exe from this repository and run it!

---

 ## How to Connect and Control a Remote PC

### Launch the Application on your PC
![115](https://github.com/user-attachments/assets/ee756744-bf65-43b5-bc2f-3ea7f8ba13c0)

### In the main menu, click on "Connect to Computer"
![116](https://github.com/user-attachments/assets/e859f79a-117a-410f-84ff-689d4ba9ccfd)

### Enter the IP address of the target computer and password (the server) into the input field
![117](https://github.com/user-attachments/assets/d6cc1f7e-6cde-49ea-8133-f27b537c0a1d)

### Select the network adapter you want to use for the connection.
🛠️ If you’re unsure which adapter corresponds to your local IP, try a few until you find the one that connects successfully
![118](https://github.com/user-attachments/assets/cfc48943-5548-4c10-b6b4-ed03feb897d8)

### Wait for the connection to be approved
![119](https://github.com/user-attachments/assets/143c5ac7-082b-4797-b7b4-ef412bdce1f3)

### If the connection is approved - you can control the mouse and keyboard, send files, and disconnect at any time!
![120](https://github.com/user-attachments/assets/e26c9e97-1852-4b8d-ac9b-21852142adac)


 ## How to Share Your (Computer Act as the Server)

### Launch the Application on your PC
![115](https://github.com/user-attachments/assets/3cc86695-acc0-491a-9468-0ab31dced5a6)

### In the main menu, click on "Share My Computer"
![121](https://github.com/user-attachments/assets/1e0b5a41-77d5-4f0a-9465-dfec2960befd)

### Set a password that will be used to authenticate incoming connections
![122](https://github.com/user-attachments/assets/3ede47dd-715b-44c7-8af0-1d748b9531c6)

### Select the appropriate network adapter to use for listening
🛠️ Use trial and error to find the correct network adapter that corresponds to your PC’s IP address
![image](https://github.com/user-attachments/assets/0fcc31b2-71f5-405c-84df-323f909281b3)

### If you have more than one monitor, you can choose which one to share
![45](https://github.com/user-attachments/assets/9160aa5f-5a15-47ba-bd97-3838258bec14)

### When a client attempts to connect, a prompt will appear
![123](https://github.com/user-attachments/assets/41eaa988-abc9-4482-9303-84bb6deeb246)

### And that's it! If you decide to approve, the client will now have control over your screen - keyboard and mouse
![124](https://github.com/user-attachments/assets/209dd5bc-ec6c-4520-b423-5c236b5cbfd3)

---

*Built with passion, precision, and lots of packets ⚙️*
