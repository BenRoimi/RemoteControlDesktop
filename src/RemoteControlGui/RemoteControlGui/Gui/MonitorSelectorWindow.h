#include <wx/wx.h>
#include <wx/listbox.h>
#include "../Infrastructure/Server.h"

class MonitorSelectorWindow : public wxFrame {
public:
    MonitorSelectorWindow(wxWindow* parent, Server* serverObj);

private:
    void OnSelect(wxCommandEvent& event);

    wxListBox* monitorListBox;
    std::vector<MonitorInfo> availableMonitors;

    void PopulateMonitorList();

    Server* server;
};