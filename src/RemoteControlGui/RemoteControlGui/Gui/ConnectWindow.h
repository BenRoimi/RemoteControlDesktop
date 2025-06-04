#pragma once

#include <wx/wx.h>
#include "../Infrastructure/Client.h"

class ConnectWindow : public wxFrame {
public:
    ConnectWindow(wxWindow* parent);

private:
    wxTextCtrl* ipEntry;
    wxTextCtrl* passwordEntry;
    wxCheckBox* showPasswordCheckbox;
    Client* client;
    wxWindow* parentWindow;
    bool createdClient;

    void OnConnect(wxCommandEvent& event);
    void OnBack(wxCommandEvent& event);
    void OnTogglePassword(wxCommandEvent& event);
};
