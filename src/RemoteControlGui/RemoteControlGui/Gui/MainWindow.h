#pragma once

#include <wx/wx.h>

class MainWindow : public wxFrame {
public:
    MainWindow();
private:
    void OnConnect(wxCommandEvent& event);
    void OnWait(wxCommandEvent& event);
};
