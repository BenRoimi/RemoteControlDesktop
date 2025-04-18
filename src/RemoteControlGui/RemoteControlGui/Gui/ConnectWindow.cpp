#include "ConnectWindow.h"
#include "ConnectingWindow.h"
#include <regex>

bool IsValidIP(const wxString& ip) {
    std::regex ipRegex(R"(^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$)");
    return std::regex_match(std::string(ip.mb_str()), ipRegex);
}

ConnectWindow::ConnectWindow(wxWindow* parent)
    : wxFrame(parent, wxID_ANY, "Connect to IP", wxDefaultPosition, wxSize(400, 250)) {

    wxPanel* panel = new wxPanel(this);
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    // IP Entry Field
    ipEntry = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize);
    sizer->Add(new wxStaticText(panel, wxID_ANY, "Enter IP:"), 0, wxLEFT | wxTOP, 10);
    sizer->Add(ipEntry, 0, wxALL | wxEXPAND, 10);

    // Password Entry Field
    passwordEntry = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
    sizer->Add(new wxStaticText(panel, wxID_ANY, "Enter Password:"), 0, wxLEFT | wxTOP, 10);
    sizer->Add(passwordEntry, 0, wxALL | wxEXPAND, 10);

    // Connect Button
    wxButton* connectBtn = new wxButton(panel, wxID_ANY, "Connect");
    sizer->Add(connectBtn, 0, wxALL | wxEXPAND, 10);
    connectBtn->Bind(wxEVT_BUTTON, &ConnectWindow::OnConnect, this);

    panel->SetSizer(sizer);
}

void ConnectWindow::OnConnect(wxCommandEvent& event) {
    wxString ip = ipEntry->GetValue();
    wxString password = passwordEntry->GetValue();

    if (!IsValidIP(ip)) {
        wxMessageBox("Invalid IP address. Please enter a valid IPv4 address.", "Error", wxOK | wxICON_ERROR);
        return;
    }

    if (password.IsEmpty()) {
        wxMessageBox("Password cannot be empty. Please enter a valid password.", "Error", wxOK | wxICON_ERROR);
        return;
    }

    // Proceed to the next window (pass both IP and password)
    Client* client = new Client();
    ConnectingWindow* connectingWindow = new ConnectingWindow(this, ip, password, client);
    connectingWindow->Show();
    Hide();

    std::thread t(&ConnectingWindow::connectToServer, connectingWindow);
    t.detach();
}