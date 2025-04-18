#pragma once

#include <wx/wx.h>
#include "../Infrastructure/Server.h"

class AcceptConnectionWindow : public wxFrame
{
public:
    AcceptConnectionWindow(wxWindow* parent, Server* server);

private:
    wxStaticText* messageText;
    wxButton* acceptButton;
    wxButton* rejectButton;
    
    Server* server;

    void OnAcceptClicked(wxCommandEvent& event);
    void OnRejectClicked(wxCommandEvent& event);

    wxDECLARE_EVENT_TABLE();
};