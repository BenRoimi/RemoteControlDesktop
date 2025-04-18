#pragma once

#include <wx/wx.h>

class ConnectWindow : public wxFrame {
public:
    ConnectWindow(wxWindow* parent);
private:
    wxTextCtrl* ipEntry;
    wxTextCtrl* passwordEntry;

    void OnConnect(wxCommandEvent& event);
    
};
