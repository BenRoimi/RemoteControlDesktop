#include "EnterPasswordWindow.h"
#include "WaitWindow.h"

wxBEGIN_EVENT_TABLE(EnterPasswordWindow, wxFrame)
EVT_BUTTON(1001, EnterPasswordWindow::OnWaitConnectionClicked)
wxEND_EVENT_TABLE()

EnterPasswordWindow::EnterPasswordWindow(wxWindow* parent)
    : wxFrame(parent, wxID_ANY, "EnterPassword Window", wxDefaultPosition, wxSize(400, 250))
{

    wxPanel* panel = new wxPanel(this, wxID_ANY);

    wxStaticText* passwordLabel = new wxStaticText(panel, wxID_ANY, "Enter Password:", wxPoint(20, 20));
    passwordInput = new wxTextCtrl(panel, wxID_ANY, "", wxPoint(130, 15), wxSize(130, -1), wxTE_PASSWORD);

    waitConnectionButton = new wxButton(panel, 1001, "Wait Connection", wxPoint(90, 60), wxSize(120, 30));

    Centre();
}

void EnterPasswordWindow::OnWaitConnectionClicked(wxCommandEvent& event)
{
    WaitWindow* waitWindow = new WaitWindow(this, passwordInput->GetValue());
    waitWindow->Show();
    Hide();
    std::thread t(&WaitWindow::startWaiting, waitWindow);
    t.detach();
   
}
