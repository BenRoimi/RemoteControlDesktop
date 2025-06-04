#include "EnterPasswordWindow.h"
#include "WaitWindow.h"

#include <wx/stattext.h>
#include <wx/sizer.h>
#include <thread>

wxBEGIN_EVENT_TABLE(EnterPasswordWindow, wxFrame)
EVT_BUTTON(1001, EnterPasswordWindow::OnWaitConnectionClicked)
EVT_BUTTON(1002, EnterPasswordWindow::OnTogglePassword)
EVT_BUTTON(1003, EnterPasswordWindow::OnBackClicked)
wxEND_EVENT_TABLE()

EnterPasswordWindow::EnterPasswordWindow(wxWindow* parent)
    : wxFrame(parent, wxID_ANY, "Set Password", wxDefaultPosition, wxSize(600, 400)),
    passwordVisible(false)
{
    SetMinSize(wxSize(600, 400));
    wxPanel* panel = new wxPanel(this, wxID_ANY);

    wxBoxSizer* outerSizer = new wxBoxSizer(wxVERTICAL);

    // Back button row
    wxBoxSizer* topBarSizer = new wxBoxSizer(wxHORIZONTAL);
    wxButton* backButton = new wxButton(panel, 1003, "< Back", wxDefaultPosition, wxSize(70, 30));
    backButton->SetFont(wxFontInfo(9));
    backButton->SetBackgroundColour(wxColour(51, 204, 51));
    topBarSizer->Add(backButton, 0, wxLEFT | wxTOP, 10);
    outerSizer->Add(topBarSizer, 0, wxALIGN_LEFT);

    // Main form
    wxBoxSizer* formSizer = new wxBoxSizer(wxVERTICAL);

    wxStaticText* passwordLabel = new wxStaticText(panel, wxID_ANY, "Set Password:");
    passwordLabel->SetFont(wxFontInfo(12).Bold());
    passwordLabel->SetForegroundColour(wxColour(255, 255, 255));
    formSizer->Add(passwordLabel, 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 10);

    wxBoxSizer* passwordRowSizer = new wxBoxSizer(wxHORIZONTAL);

    passwordInput = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxSize(200, 30), wxTE_PASSWORD);
    passwordInput->SetFont(wxFontInfo(11));
    passwordRowSizer->Add(passwordInput, 0, wxALL, 5);

    togglePasswordBtn = new wxButton(panel, 1002, "Show", wxDefaultPosition, wxSize(50, 30));
    togglePasswordBtn->SetFont(wxFontInfo(9));
    passwordRowSizer->Add(togglePasswordBtn, 0, wxALL, 5);

    formSizer->Add(passwordRowSizer, 0, wxALIGN_CENTER_HORIZONTAL);

    waitConnectionButton = new wxButton(panel, 1001, "Wait for Connection", wxDefaultPosition, wxSize(180, 40));
    waitConnectionButton->SetFont(wxFontInfo(11).Bold());
    waitConnectionButton->SetBackgroundColour(wxColour(51, 204, 51));
    waitConnectionButton->SetForegroundColour(*wxBLACK);
    waitConnectionButton->SetWindowStyle(wxBORDER_SIMPLE);
    formSizer->Add(waitConnectionButton, 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 15);

    outerSizer->AddStretchSpacer(1);
    outerSizer->Add(formSizer, 0, wxALIGN_CENTER);
    outerSizer->AddStretchSpacer(1);

    panel->SetSizer(outerSizer);
    panel->SetBackgroundColour(wxColour(26, 26, 26));
    Centre();
}

void EnterPasswordWindow::OnWaitConnectionClicked(wxCommandEvent& event)
{
    wxString password = passwordInput->GetValue().Trim();

    if (password.IsEmpty()) {
        wxMessageBox("Password cannot be empty.", "Input Error", wxOK | wxICON_WARNING);
        return;
    }

    WaitWindow* waitWindow = new WaitWindow(this, password);
    waitWindow->Show();
    Hide();

    std::thread t(&WaitWindow::startWaiting, waitWindow);
    t.detach();
}

void EnterPasswordWindow::OnTogglePassword(wxCommandEvent& event)
{
    long insertionPoint = passwordInput->GetInsertionPoint();
    wxString currentValue = passwordInput->GetValue();

    int style = passwordVisible ? wxTE_PASSWORD : 0;
    passwordVisible = !passwordVisible;

    togglePasswordBtn->SetLabel(passwordVisible ? "Hide" : "Show");

    // Recreate text control with new style
    wxWindow* parent = passwordInput->GetParent();
    wxSizer* sizer = passwordInput->GetContainingSizer();

    sizer->Detach(passwordInput);
    passwordInput->Destroy();

    passwordInput = new wxTextCtrl(parent, wxID_ANY, currentValue, wxDefaultPosition, wxSize(200, 30), style);
    passwordInput->SetFont(wxFontInfo(11));
    passwordInput->SetInsertionPoint(insertionPoint);

    sizer->Insert(0, passwordInput, 0, wxALL, 5);
    parent->Layout();
}

void EnterPasswordWindow::OnBackClicked(wxCommandEvent& event)
{
    if (GetParent()) {
        GetParent()->Show();
    }
    Close();
}

