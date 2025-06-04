#include "WaitWindow.h"
#include "AcceptConnectionWindow.h"
#include <wx/stattext.h>
#include <wx/timer.h>
#include <wx/sizer.h>
#include <wx/msgdlg.h>

WaitWindow::WaitWindow(wxWindow* parent, wxString password)
    : wxFrame(parent, wxID_ANY, "Waiting", wxDefaultPosition, wxSize(600, 400)),
    dotCount(0), serverPassword(std::string(password.mb_str()))
{
    server = new Server(std::string(password.mb_str()));

    wxPanel* panel = new wxPanel(this);
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    wxString ip = "My IP: " + server->getSrcIP();

    // Setup animated text
    ipLabel = new wxStaticText(panel, wxID_ANY, ip, wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL);
    ipLabel->SetFont(wxFontInfo(14).Bold());
    ipLabel->SetForegroundColour(wxColour(255, 255, 255));
    waitingLabel = new wxStaticText(panel, wxID_ANY, "Waiting for connection", wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL);
    waitingLabel->SetForegroundColour(wxColour(255, 255, 255));
    waitingLabel->SetFont(wxFontInfo(14).Bold());
    sizer->AddStretchSpacer(1);
    sizer->Add(waitingLabel, 0, wxALIGN_CENTER_HORIZONTAL | wxALL, 20);
    sizer->Add(ipLabel, 0, wxALIGN_CENTER_HORIZONTAL | wxALL, 20);
    sizer->AddStretchSpacer(1);

    panel->SetSizer(sizer);
    panel->SetBackgroundColour(wxColour(26, 26, 26));

    // Setup animation timer
    timer = new wxTimer(this, wxID_ANY);
    Bind(wxEVT_TIMER, &WaitWindow::OnTimerTick, this, timer->GetId());
    timer->Start(500); // 500ms interval for animation

    Centre();
}

WaitWindow::WaitWindow(wxWindow* parent, Server* server)
    : wxFrame(parent, wxID_ANY, "Waiting", wxDefaultPosition, wxSize(600, 400)),
    dotCount(0), server(server)
{
    wxPanel* panel = new wxPanel(this);
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    wxString ip = "My IP: " + server->getSrcIP();

    // Setup animated text
    ipLabel = new wxStaticText(panel, wxID_ANY, ip, wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL);
    ipLabel->SetFont(wxFontInfo(14).Bold());
    waitingLabel = new wxStaticText(panel, wxID_ANY, "Waiting for connection", wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL);
    waitingLabel->SetFont(wxFontInfo(14).Bold());
    sizer->AddStretchSpacer(1);
    sizer->Add(waitingLabel, 0, wxALIGN_CENTER_HORIZONTAL | wxALL, 20);
    sizer->Add(ipLabel, 0, wxALIGN_CENTER_HORIZONTAL | wxALL, 20);
    sizer->AddStretchSpacer(1);

    panel->SetSizer(sizer);
    panel->SetBackgroundColour(wxColour(255, 255, 255));

    // Setup animation timer
    timer = new wxTimer(this, wxID_ANY);
    Bind(wxEVT_TIMER, &WaitWindow::OnTimerTick, this, timer->GetId());
    timer->Start(500); // 500ms interval for animation

    Centre();
}

void WaitWindow::startWaiting()
{
    while (true) {
        if (!server->WaitForConnection()) {
            wxMessageBox("Someone tried to connect with wrong credentials or protocol. Keep yourself safe!", "Error", wxOK | wxICON_ERROR);
            //delete server;
            //server = new Server(serverPassword);
        }
        else {
            break;
        }
    }
    

    wxTheApp->CallAfter([this]() {
        timer->Stop();
        AcceptConnectionWindow* acceptConnectionWindow = new AcceptConnectionWindow(this, server);
        acceptConnectionWindow->Show();
        Hide();
        });
}

void WaitWindow::OnTimerTick(wxTimerEvent& event)
{
    dotCount = (dotCount + 1) % 4; // Cycle through 0–3 dots
    wxString baseText = "Waiting for connection";
    wxString dots(dotCount, '.');
    waitingLabel->SetLabel(baseText + dots);
}
