#include "MainWindow.h"
#include "ConnectWindow.h"
#include "EnterPasswordWindow.h"

MainWindow::MainWindow()
    : wxFrame(nullptr, wxID_ANY, "Main Screen", wxDefaultPosition, wxSize(600, 400)) {
    SetMinSize(wxSize(600, 400));
    wxPanel* panel = new wxPanel(this);

    // Use a box sizer to center everything vertically and horizontally
    wxBoxSizer* outerSizer = new wxBoxSizer(wxVERTICAL);
    wxBoxSizer* contentSizer = new wxBoxSizer(wxVERTICAL);

    // Headline
    wxStaticText* headline = new wxStaticText(panel, wxID_ANY, "Welcome to Remote PC App", wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL);
    wxFont headlineFont(wxFontInfo(20).Bold());
    headline->SetFont(headlineFont);
    headline->SetForegroundColour(wxColour(255, 255, 255));
    contentSizer->Add(headline, 0, wxTOP | wxBOTTOM | wxALIGN_CENTER_HORIZONTAL, 20);

    // Connect Button
    wxButton* connectBtn = new wxButton(panel, wxID_ANY, "Connect to Computer", wxDefaultPosition, wxSize(250, 50));
    connectBtn->SetFont(wxFontInfo(11).Bold());
    connectBtn->SetBackgroundColour(wxColour(51, 204, 51));
    connectBtn->SetForegroundColour(*wxBLACK);
    connectBtn->SetWindowStyle(wxBORDER_SIMPLE);
    contentSizer->Add(connectBtn, 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 10);
    connectBtn->Bind(wxEVT_BUTTON, &MainWindow::OnConnect, this);

    // Wait Button
    wxButton* waitBtn = new wxButton(panel, wxID_ANY, "Share My Computer", wxDefaultPosition, wxSize(250, 50));
    waitBtn->SetFont(wxFontInfo(11).Bold());
    waitBtn->SetBackgroundColour(wxColour(51, 204, 51));
    waitBtn->SetForegroundColour(*wxBLACK);
    waitBtn->SetWindowStyle(wxBORDER_SIMPLE);
    contentSizer->Add(waitBtn, 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 10);
    waitBtn->Bind(wxEVT_BUTTON, &MainWindow::OnWait, this);

    // Vertical centering
    outerSizer->AddStretchSpacer(1);
    outerSizer->Add(contentSizer, 0, wxALIGN_CENTER);
    outerSizer->AddStretchSpacer(1);

    panel->SetSizer(outerSizer);
    panel->SetBackgroundColour(wxColour(26, 26, 26));
    Centre();
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
