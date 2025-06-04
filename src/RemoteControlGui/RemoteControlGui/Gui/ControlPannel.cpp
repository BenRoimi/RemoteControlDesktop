#include "ControlPanel.h"
#include <wx/filedlg.h>

wxBEGIN_EVENT_TABLE(ControlPanel, wxFrame)
EVT_BUTTON(1001, ControlPanel::OnTerminate)
EVT_BUTTON(1002, ControlPanel::OnSendFile)
wxEND_EVENT_TABLE()

ControlPanel::ControlPanel(wxWindow* parent, Client* clientObj, FileTransfer* fileTransferObj)
    : wxFrame(parent, wxID_ANY, "Control Panel", wxDefaultPosition, wxSize(280, 180),
        wxDEFAULT_FRAME_STYLE & ~(wxRESIZE_BORDER | wxMAXIMIZE_BOX)), // cleaner frame
    client(clientObj), fileTransfer(fileTransferObj)
{
    std::thread t(&ControlPanel::checkDisconnectionThread, this);
    t.detach();

    wxPanel* panel = new wxPanel(this, wxID_ANY);
    panel->SetBackgroundColour(wxColour(26, 26, 26)); // light gray background

    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

    wxFont buttonFont(12, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD);

    m_terminateBtn = new wxButton(panel, 1001, "Disconnect", wxDefaultPosition, wxSize(200, 40));
    m_terminateBtn->SetBackgroundColour(wxColour(220, 53, 69)); // Bootstrap red
    m_terminateBtn->SetForegroundColour(*wxWHITE);
    m_terminateBtn->SetFont(buttonFont);

    m_sendFileBtn = new wxButton(panel, 1002, "Send File", wxDefaultPosition, wxSize(200, 40));
    m_sendFileBtn->SetBackgroundColour(wxColour(40, 167, 69)); // Bootstrap green
    m_sendFileBtn->SetForegroundColour(*wxWHITE);
    m_sendFileBtn->SetFont(buttonFont);

    mainSizer->AddSpacer(20);
    mainSizer->Add(m_terminateBtn, 0, wxALIGN_CENTER | wxALL, 5);
    mainSizer->Add(m_sendFileBtn, 0, wxALIGN_CENTER | wxALL, 5);
    mainSizer->AddSpacer(20);

    panel->SetSizer(mainSizer);

    this->SetMinSize(wxSize(280, 180));
    Center();
    Show();
}

void ControlPanel::OnTerminate(wxCommandEvent& event)
{
    this->client->requestDisconnection();
}

void ControlPanel::OnSendFile(wxCommandEvent& event)
{
    wxFileDialog openFileDialog(this, _("Open file"), "", "",
        "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    if (openFileDialog.ShowModal() == wxID_CANCEL)
        return; // The user canceled

    wxString path = openFileDialog.GetPath();
    
    if (fileTransfer->connectionFree()) {
        fileTransfer->sendFile(std::string(path.mb_str()));
    }
    else {
        wxMessageBox("Connection is not free");
    }
}

void ControlPanel::checkDisconnectionThread()
{
    while (true) {
        if (this->client->disconnected()) {
            wxTheApp->CallAfter([this]() {
                wxMessageBox(this->client->getLastServerError(),
                    "Connection Lost", wxOK | wxICON_ERROR, this);

                wxTheApp->ExitMainLoop();
                });

            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
