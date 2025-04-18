#pragma once
#include "MonitorSelectorWindow.h"
#include <sstream>
#include <vector>

// Global vector to temporarily store monitors during enumeration
std::vector<MonitorInfo> monitorsTemp;
BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) {
    MONITORINFOEX monitorInfo;
    monitorInfo.cbSize = sizeof(MONITORINFOEX);

    if (GetMonitorInfo(hMonitor, &monitorInfo)) {
        MonitorInfo info;

        std::wstring wsname(monitorInfo.szDevice);
        std::string namestr(wsname.begin(), wsname.end());
        info.name = namestr; // Convert name to std::string
        info.width = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
        info.height = monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top;
        info.x = monitorInfo.rcMonitor.left;
        info.y = monitorInfo.rcMonitor.top;

        monitorsTemp.push_back(info); // Add monitor to the temp list
    }

    return TRUE; // Continue enumeration
}

MonitorSelectorWindow::MonitorSelectorWindow(wxWindow* parent, Server* serverObj)
    : wxFrame(parent, wxID_ANY, "Select Monitor", wxDefaultPosition, wxSize(400, 300)),
    server(serverObj)
{
    /* Dummy monitor data - replace with actual population logic
    availableMonitors = {
        {"Primary Monitor", 1920, 1080, 0, 0},
        {"Secondary Monitor", 1280, 1024, 1920, 0}
    };*/

    monitorsTemp.clear(); // Clear the temporary list
   if (!EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, 0)) {
       std::cerr << "Failed to enumerate monitors." << std::endl;
       return;
   }
   availableMonitors = monitorsTemp;

    wxPanel* panel = new wxPanel(this);
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);

    monitorListBox = new wxListBox(panel, wxID_ANY);
    PopulateMonitorList();
    sizer->Add(monitorListBox, 1, wxEXPAND | wxALL, 10);

    monitorListBox->Bind(wxEVT_LISTBOX, &MonitorSelectorWindow::OnSelect, this);

    panel->SetSizer(sizer);
    Centre();
}

void MonitorSelectorWindow::PopulateMonitorList() {
    for (const auto& monitor : availableMonitors) {
        std::ostringstream ss;
        ss << monitor.name << " (" << monitor.width << "x" << monitor.height << " at " << monitor.x << "," << monitor.y << ")";
        monitorListBox->AppendString(ss.str());
    }
}

void MonitorSelectorWindow::OnSelect(wxCommandEvent& event) {
    int index = event.GetSelection();
    if (index >= 0 && index < static_cast<int>(availableMonitors.size())) {
        server->setMonitor(availableMonitors[index]);
        std::vector<unsigned int> channelsToRemove; // example for tests
        channelsToRemove.push_back(4);
        channelsToRemove.push_back(5);
        Hide();
        this->server->handleSettingsExchange(channelsToRemove);
        this->server->startCapture(FPS);
        this->server->updateChannelData();
        //wxMessageBox("Selected: " + monitorListBox->GetString(index), "Monitor Selected", wxOK | wxICON_INFORMATION);
    }
}
