#include "AcceptConnectionWindow.h"
#include "SettingNagotiationWindow.h"
#include "WaitWindow.h"

wxBEGIN_EVENT_TABLE(AcceptConnectionWindow, wxFrame)
EVT_BUTTON(1001, AcceptConnectionWindow::OnAcceptClicked)
EVT_BUTTON(1002, AcceptConnectionWindow::OnRejectClicked)
wxEND_EVENT_TABLE()



AcceptConnectionWindow::AcceptConnectionWindow(wxWindow* parent, Server* server)
    : wxFrame(nullptr, wxID_ANY, "Incoming Connection", wxDefaultPosition, wxSize(600, 400)), server(server)
{
    SetMinSize(wxSize(600, 400));

    wxPanel* panel = new wxPanel(this, wxID_ANY);
    panel->SetBackgroundColour(wxColour(26, 26, 26));

    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

    // Add stretchable spacer at top
    mainSizer->AddStretchSpacer(1);

    // Title Message
    wxString message = server->getDstIP() + " is requesting a connection.";
   
    messageText = new wxStaticText(panel, wxID_ANY, message, wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER);
    messageText->SetFont(wxFont(16, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    messageText->Wrap(500);
    messageText->SetForegroundColour(wxColour(255, 255, 255));

    mainSizer->Add(messageText, 0, wxALIGN_CENTER | wxTOP | wxBOTTOM, 30);

    // Buttons sizer
    wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);

    acceptButton = new wxButton(panel, 1001, "Accept", wxDefaultPosition, wxSize(120, 50));
    acceptButton->SetBackgroundColour(wxColour(0, 153, 0));
    acceptButton->SetForegroundColour(*wxWHITE);
    acceptButton->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));

    rejectButton = new wxButton(panel, 1002, "Reject", wxDefaultPosition, wxSize(120, 50));
    rejectButton->SetBackgroundColour(wxColour(204, 0, 0));
    rejectButton->SetForegroundColour(*wxWHITE);
    rejectButton->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));

    buttonSizer->Add(acceptButton, 0, wxALL, 10);
    buttonSizer->Add(rejectButton, 0, wxALL, 10);

    mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER | wxBOTTOM, 30);

    // Add stretchable spacer at bottom
    mainSizer->AddStretchSpacer(1);

    panel->SetSizer(mainSizer);
    Centre();
}



void AcceptConnectionWindow::OnAcceptClicked(wxCommandEvent& event)
{
    SettingNagotiationWindow* settingNagotiationWindow = new SettingNagotiationWindow(this, server);
    settingNagotiationWindow->Show();
    Hide();
    std::thread t(&SettingNagotiationWindow::serverAcceptConnection, settingNagotiationWindow);
    t.detach();
}

void AcceptConnectionWindow::OnRejectClicked(wxCommandEvent& event)
{
    this->server->denyAccess("Connection rejected");
    this->server->restartTCPData();
    //wxWindow* parent = GetParent();
    //if (parent) {
    //    parent->Show(); // Show WaitWindow again
    //}

    WaitWindow* waitWindow = new WaitWindow(this, server);
    waitWindow->Show();
    Hide();

    std::thread t(&WaitWindow::startWaiting, waitWindow);
    t.detach();
}
