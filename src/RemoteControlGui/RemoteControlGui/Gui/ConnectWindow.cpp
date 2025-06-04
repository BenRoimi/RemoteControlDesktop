#include "ConnectWindow.h"
#include "ConnectingWindow.h"
#include <regex>

bool IsValidIP(const wxString& ip) {
    std::regex ipRegex(R"(^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$)");
    return std::regex_match(std::string(ip.mb_str()), ipRegex);
}

ConnectWindow::ConnectWindow(wxWindow* parent)
    : wxFrame(parent, wxID_ANY, "Connect to Remote PC", wxDefaultPosition, wxSize(600, 400)),
    parentWindow(parent), createdClient(false)
{
    SetMinSize(wxSize(600, 400));

    wxPanel* panel = new wxPanel(this);
    panel->SetBackgroundColour(*wxWHITE);

    // Outer sizer contains everything (Back button + Main content)
    wxBoxSizer* outerSizer = new wxBoxSizer(wxVERTICAL);

    // Back button
    wxBoxSizer* topBarSizer = new wxBoxSizer(wxHORIZONTAL);
    wxButton* backButton = new wxButton(panel, wxID_ANY, "< Back", wxDefaultPosition, wxSize(80, 30));
    backButton->SetFont(wxFontInfo(9));
    backButton->SetBackgroundColour(wxColour(51, 204, 51));
    topBarSizer->Add(backButton, 0, wxLEFT | wxTOP, 10);
    backButton->Bind(wxEVT_BUTTON, &ConnectWindow::OnBack, this);
    outerSizer->Add(topBarSizer, 0, wxALIGN_LEFT);

    // Main sizer to center form content
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    mainSizer->AddStretchSpacer(1);

    // Content
    wxBoxSizer* contentSizer = new wxBoxSizer(wxVERTICAL);

    auto* ipLabel = new wxStaticText(panel, wxID_ANY, "Enter IP Address:");
    ipLabel->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    ipLabel->SetForegroundColour(wxColour(255, 255, 255));
    contentSizer->Add(ipLabel, 0, wxALIGN_CENTER | wxALL, 5);

    ipEntry = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(250, -1));
    contentSizer->Add(ipEntry, 0, wxALIGN_CENTER | wxALL, 5);

    auto* pwLabel = new wxStaticText(panel, wxID_ANY, "Enter Password:");
    pwLabel->SetFont(wxFont(11, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    pwLabel->SetForegroundColour(wxColour(255, 255, 255));
    contentSizer->Add(pwLabel, 0, wxALIGN_CENTER | wxALL, 5);

    passwordEntry = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(250, -1), wxTE_PASSWORD);
    contentSizer->Add(passwordEntry, 0, wxALIGN_CENTER | wxALL, 5);

    // Add Show Password checkbox
    showPasswordCheckbox = new wxCheckBox(panel, wxID_ANY, "Show Password");
    contentSizer->Add(showPasswordCheckbox, 0, wxALIGN_CENTER | wxBOTTOM, 10);
    showPasswordCheckbox->SetForegroundColour(wxColour(255, 255, 255));
    showPasswordCheckbox->Bind(wxEVT_CHECKBOX, &ConnectWindow::OnTogglePassword, this);

    wxButton* connectBtn = new wxButton(panel, wxID_ANY, "Connect", wxDefaultPosition, wxSize(120, 35));
    connectBtn->SetFont(wxFont(10, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    contentSizer->Add(connectBtn, 0, wxALIGN_CENTER | wxALL, 15);
    connectBtn->SetBackgroundColour(wxColour(51, 204, 51));
    connectBtn->Bind(wxEVT_BUTTON, &ConnectWindow::OnConnect, this);

    mainSizer->Add(contentSizer, 0, wxALIGN_CENTER);
    mainSizer->AddStretchSpacer(1);

    outerSizer->Add(mainSizer, 1, wxEXPAND);
    panel->SetSizer(outerSizer);
    panel->SetBackgroundColour(wxColour(26, 26, 26));
    Centre();
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

    // Proceed to the next window
    if (!createdClient) {
        this->client = new Client();
        this->createdClient = true;
    }
    
    ConnectingWindow* connectingWindow = new ConnectingWindow(this, ip, password, this->client);
    connectingWindow->Show();
    Hide();

    std::thread t(&ConnectingWindow::connectToServer, connectingWindow);
    t.detach();
}

void ConnectWindow::OnBack(wxCommandEvent& event) {
    if (parentWindow) {
        parentWindow->Show();
    }
    Close();
}

void ConnectWindow::OnTogglePassword(wxCommandEvent& event) {
    long style = passwordEntry->GetWindowStyle();

    wxString currentText = passwordEntry->GetValue();
    wxPoint pos = passwordEntry->GetPosition();
    wxSize size = passwordEntry->GetSize();

    int insertionPoint = passwordEntry->GetInsertionPoint();

    // Destroy old password control
    passwordEntry->Destroy();

    // Create new one with/without wxTE_PASSWORD
    if (showPasswordCheckbox->IsChecked()) {
        passwordEntry = new wxTextCtrl(this, wxID_ANY, currentText, pos, size);
    }
    else {
        passwordEntry = new wxTextCtrl(this, wxID_ANY, currentText, pos, size, wxTE_PASSWORD);
    }

    passwordEntry->SetInsertionPoint(insertionPoint);
    Layout();  // Refresh layout
}
