#include "ConnectingWindow.h"

ConnectingWindow::ConnectingWindow(wxWindow* parent, const wxString& ip, const wxString& password, Client* client)
    : wxFrame(parent, wxID_ANY, "Connecting to " + ip, wxDefaultPosition, wxSize(400, 200)), ip(ip), password(password), client(client)
{
    wxPanel* panel = new wxPanel(this);

    // Use a vertical box sizer to center content
    wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

    // Static text
    wxStaticText* label = new wxStaticText(panel, wxID_ANY, "Connecting, please wait...");
    label->SetFont(wxFont(12, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
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
}

void ConnectingWindow::connectToServer()
{
    if (!client->connect(ip.ToStdString(), password.ToStdString())) {
        wxMessageBox("error", "Error", wxOK | wxICON_ERROR);
    }
    wxTheApp->CallAfter([this]() {
        Hide();
        client->updateChannelsData();
        });
}
