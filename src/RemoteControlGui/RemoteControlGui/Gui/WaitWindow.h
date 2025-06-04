#pragma once

#include <wx/wx.h>
#include <wx/timer.h>
#include "../Infrastructure/Server.h"

class WaitWindow : public wxFrame
{
public:
    WaitWindow(wxWindow* parent, wxString password);
    WaitWindow(wxWindow* parent, Server* server);
    void startWaiting();

private:
    Server* server;
    std::string serverPassword;
    wxStaticText* ipLabel;
    wxStaticText* waitingLabel;
    wxTimer* timer;
    int dotCount;

    void OnTimerTick(wxTimerEvent& event);
};