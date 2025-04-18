#pragma once

const enum class CodeId {
	Error,
	Connect,
    AesKeyRequest,
    SettingsExchangeRequest,
    SettingsExchangeResponse,
    SendAction,
    DissconnectRequest,
    DissconnectResponse,
    SendScreenshot
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
    ActionType type; // Type of action
    int x;           // X coordinate (for MouseMove)
    int y;           // Y coordinate (for MouseMove)
    MouseAction button;
    char key;        // Key character (for KeyPress)
};

// Structure to hold monitor information
struct MonitorInfo {
    std::string name;
    int width;
    int height;
    // the monitor position in the overall desktop (compared to the primary one)
    int x;
    int y;
};