#pragma once

#include <wx/wx.h>
#include "../Infrastructure/Server.h"

class WaitWindow : public wxFrame {
public:
    WaitWindow(wxWindow* parent, wxString password);
    void startWaiting();
private:
    Server* server;
};