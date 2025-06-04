#include "SettingNagotiationWindow.h"
#include "MonitorSelectorWindow.h"

SettingNagotiationWindow::SettingNagotiationWindow(wxWindow* parent, Server* server)
    : wxFrame(parent, wxID_ANY, "SettingsExchange", wxDefaultPosition, wxSize(600, 400)), server(server)
{
    SetMinSize(wxSize(600, 400));

    wxPanel* panel = new wxPanel(this);

    // Use a vertical box sizer to center content
    wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

    // Static text
    wxStaticText* label = new wxStaticText(panel, wxID_ANY, "Connecting, please wait...");
    label->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
    label->Wrap(380); // optional: wrap text if needed

    vbox->AddStretchSpacer(1);
    vbox->Add(label, 0, wxALIGN_CENTER | wxBOTTOM, 10);

    // Animation control
    wxAnimationCtrl* animCtrl = new wxAnimationCtrl(panel, wxID_ANY, wxNullAnimation);
    wxAnimation anim;

    if (anim.LoadFile("loading.gif", wxANIMATION_TYPE_GIF)) {
        animCtrl->SetAnimation(anim);
        animCtrl->Play();
    }
    else {
        wxMessageBox("Failed to load loading.gif", "Error", wxOK | wxICON_ERROR);
    }

    vbox->Add(animCtrl, 0, wxALIGN_CENTER);
    vbox->AddStretchSpacer(1);

    panel->SetSizer(vbox);
    panel->SetBackgroundColour(wxColour(255, 255, 255));
    Centre();
}

void SettingNagotiationWindow::serverAcceptConnection()
{
    this->server->AcceptConenction();

    wxTheApp->CallAfter([this]() {
        MonitorSelectorWindow* monitorSelectorWindow = new MonitorSelectorWindow(this, server);
        monitorSelectorWindow->Show();
        Hide();
    });
}
