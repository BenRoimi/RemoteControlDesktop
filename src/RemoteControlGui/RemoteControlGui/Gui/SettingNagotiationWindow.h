#pragma once

#include <wx/wx.h>
#include <wx/animate.h>
#include "../Infrastructure/Server.h"

class SettingNagotiationWindow : public wxFrame {
public:
    SettingNagotiationWindow(wxWindow* parent, Server* server);
    void serverAcceptConnection();
private:
    Server* server;
};
#pragma once
