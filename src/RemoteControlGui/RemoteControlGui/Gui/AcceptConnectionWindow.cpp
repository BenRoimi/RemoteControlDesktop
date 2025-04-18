#include "AcceptConnectionWindow.h"
#include "SettingNagotiationWindow.h"

wxBEGIN_EVENT_TABLE(AcceptConnectionWindow, wxFrame)
EVT_BUTTON(1001, AcceptConnectionWindow::OnAcceptClicked)
EVT_BUTTON(1002, AcceptConnectionWindow::OnRejectClicked)
wxEND_EVENT_TABLE()



AcceptConnectionWindow::AcceptConnectionWindow(wxWindow* parent, Server* server)
    : wxFrame(nullptr, wxID_ANY, "Incoming Connection", wxDefaultPosition, wxSize(400, 150)), server(server)
{
    wxPanel* panel = new wxPanel(this, wxID_ANY);

    wxString message = server->getDstIP() + " has tried to connect.";
    messageText = new wxStaticText(panel, wxID_ANY, message, wxPoint(20, 20));

    acceptButton = new wxButton(panel, 1001, "Accept", wxPoint(80, 60), wxSize(100, 30));
    rejectButton = new wxButton(panel, 1002, "Reject", wxPoint(220, 60), wxSize(100, 30));

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
    wxMessageBox("Connection Rejected", "Info", wxOK | wxICON_WARNING);
    this->server->denyAccessAndRestart();
    
}
