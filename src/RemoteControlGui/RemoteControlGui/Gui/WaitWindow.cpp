#include "WaitWindow.h"
#include "AcceptConnectionWindow.h"

WaitWindow::WaitWindow(wxWindow* parent, wxString password) : wxFrame(parent, wxID_ANY, "Waiting", wxDefaultPosition, wxSize(400, 200)) {
    server = new Server(std::string(password.mb_str()));
    wxPanel* panel = new wxPanel(this);
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    wxString ip = server->getSrcIP();

    wxStaticText* text = new wxStaticText(panel, wxID_ANY, "Waiting for connection on " + ip, wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER);
    sizer->Add(text, 0, wxALIGN_CENTER | wxALL, 10);

    panel->SetSizer(sizer);

    //CallAfter(&WaitWindow::StartWaiting);
}

void WaitWindow::startWaiting() {
    if (!server->WaitForConnection()) {
        wxMessageBox("An error occurred.", "Error", wxOK | wxICON_ERROR);
        Close(); // or Destroy()
        return;
    }
    wxTheApp->CallAfter([this]() {
        AcceptConnectionWindow* acceptConnectionWindow = new AcceptConnectionWindow(this, server);
        acceptConnectionWindow->Show();
        Hide();
        });
}