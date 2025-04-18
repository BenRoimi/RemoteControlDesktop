#pragma once

#include <wx/wx.h>
#include <wx/animate.h>
#include "../Infrastructure/Client.h"

class ConnectingWindow : public wxFrame {
public:
    ConnectingWindow(wxWindow* parent, const wxString& ip, const wxString& password, Client* client);
    void connectToServer();
private:
    Client* client;
    wxString ip;
    wxString password;
};
