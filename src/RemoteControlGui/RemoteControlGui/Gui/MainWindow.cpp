#include "MainWindow.h"
#include "ConnectWindow.h"
#include "EnterPasswordWindow.h"

//#include "../Infrastructure/Server.h"


MainWindow::MainWindow() : wxFrame(nullptr, wxID_ANY, "Main Screen", wxDefaultPosition, wxSize(400, 300)) {
    wxPanel* panel = new wxPanel(this);
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    wxStaticText* headline = new wxStaticText(panel, wxID_ANY, "Welcome to the Connection App", wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER);
    sizer->Add(headline, 0, wxALL | wxEXPAND, 10);

    wxButton* connectBtn = new wxButton(panel, wxID_ANY, "Connect");
    sizer->Add(connectBtn, 0, wxALL | wxEXPAND, 10);
    connectBtn->Bind(wxEVT_BUTTON, &MainWindow::OnConnect, this);

    wxButton* waitBtn = new wxButton(panel, wxID_ANY, "Wait for Connection");
    sizer->Add(waitBtn, 0, wxALL | wxEXPAND, 10);
    waitBtn->Bind(wxEVT_BUTTON, &MainWindow::OnWait, this);

    panel->SetSizer(sizer);
}

void MainWindow::OnConnect(wxCommandEvent& event) {
    ConnectWindow* connectWindow = new ConnectWindow(this);
    connectWindow->Show();
    Hide();
}

void MainWindow::OnWait(wxCommandEvent& event) {
    EnterPasswordWindow* enterPasswordWindow = new EnterPasswordWindow(this);
    enterPasswordWindow->Show();
    Hide();
}
