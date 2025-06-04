#pragma once

const enum class CodeId {
	Error,
	Connect,
    AesKeyRequest,
    AesKeyResponse,
    SettingsExchangeRequest,
    SettingsExchangeResponse,
    SendAction,
    DissconnectRequest,
    DissconnectResponse,
    SendScreenshot,
    FileTransmissionRequest,
    FileTransmissionResponse,
    FileData
};

enum class ConnectionResult {
    Success,
    NoPasswordMatch,
    Timeout,
    UnknownError
};

enum class NegotiationState {
    Initial,
    Disconnected,
    ConnectionInitiation,
    SettingsExchange,
    ChannelInitiation,
    SecurityInitiation,
    FullyConnected
};

enum class ActionType {
    MouseMove,
    MouseClick,
    KeyPress
};

enum class MouseAction {
    LeftMouseDown,
    LeftMouseUp,
    RightMouseDown,
    RightMouseUp
};

struct Action {
    ActionType type;
    int x;
    int y;
    MouseAction button;
    char key;
};

struct MonitorInfo {
    std::string name;
    int width;
    int height;
    int x;
    int y;
};


