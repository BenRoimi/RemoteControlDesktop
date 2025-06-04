#pragma once
#include <wx/wx.h>
#include "../Infrastructure/Server.h"
#include "../FileTransmission/FileTransfer.h"

class ControlButtons : public wxFrame
{
public:
    ControlButtons(wxWindow* parent, const wxPoint& pos, Server* serverObj, FileTransfer* fileTransferObj);
    void OnTerminate(wxCommandEvent& event);
    void OnSendFile(wxCommandEvent& event);

private:
    wxButton* m_terminateBtn;
    wxButton* m_sendFileBtn;
    Server* server;
    FileTransfer* fileTransfer;

    wxDECLARE_EVENT_TABLE();
};
