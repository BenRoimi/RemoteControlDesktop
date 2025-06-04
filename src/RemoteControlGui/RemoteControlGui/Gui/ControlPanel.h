#pragma once
#include <wx/wx.h>
#include "../Infrastructure/Client.h"
#include "../FileTransmission/FileTransfer.h"

class ControlPanel : public wxFrame
{
public:
    ControlPanel(wxWindow* parent, Client* clientObj, FileTransfer* fileTransferObj);
    void OnTerminate(wxCommandEvent& event);
    void OnSendFile(wxCommandEvent& event);

private:
    wxButton* m_terminateBtn;
    wxButton* m_sendFileBtn;
    Client* client;
    FileTransfer* fileTransfer;

    wxDECLARE_EVENT_TABLE();
    void checkDisconnectionThread();
};
