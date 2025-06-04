#include "ControlButtons.h"

wxBEGIN_EVENT_TABLE(ControlButtons, wxFrame)
EVT_BUTTON(1001, ControlButtons::OnTerminate)
EVT_BUTTON(1002, ControlButtons::OnSendFile)
wxEND_EVENT_TABLE()

ControlButtons::ControlButtons(wxWindow* parent, const wxPoint& pos, Server* serverObj, FileTransfer* fileTransferObj)
    : wxFrame(parent, wxID_ANY, "", pos, wxSize(50, 24),
        wxSTAY_ON_TOP | wxFRAME_NO_TASKBAR | wxBORDER_NONE), server(serverObj), fileTransfer(fileTransferObj)
{
    wxPanel* panel = new wxPanel(this, wxID_ANY);
    wxBoxSizer* sizer = new wxBoxSizer(wxHORIZONTAL);

    m_terminateBtn = new wxButton(panel, 1001, "X", wxDefaultPosition, wxSize(20, 20));
    m_terminateBtn->SetBackgroundColour(*wxRED);

    m_sendFileBtn = new wxButton(panel, 1002, "F", wxDefaultPosition, wxSize(20, 20));

    sizer->Add(m_terminateBtn, 0, wxALL, 2);
    sizer->Add(m_sendFileBtn, 0, wxALL, 2);

    panel->SetSizer(sizer);
    Layout();
    Show();
}

void ControlButtons::OnTerminate(wxCommandEvent& event)
{
    //wxMessageBox("Terminate connection clicked!", "Action");
    this->server->requestDisconnection();
}

void ControlButtons::OnSendFile(wxCommandEvent& event)

{
    wxFileDialog openFileDialog(this, _("Open file"), "", "",
        "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    if (openFileDialog.ShowModal() == wxID_CANCEL)
        return; // The user canceled

    wxString path = openFileDialog.GetPath();

    if (fileTransfer->connectionFree()) {
        fileTransfer->sendFile(std::string(path.ToUTF8()));
    }
    else {
        wxMessageBox("Connection is not free");
    }
}
