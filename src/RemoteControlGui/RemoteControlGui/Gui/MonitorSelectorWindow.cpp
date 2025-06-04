#pragma once
#include "MonitorSelectorWindow.h"
#include <sstream>
#include <vector>
#include "ScreenShareWindow.h"

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
    : wxFrame(parent, wxID_ANY, "Select Monitor", wxDefaultPosition, wxSize(600, 400)),
    server(serverObj)
{
    SetMinSize(wxSize(600, 400));

    monitorsTemp.clear();
    if (!EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, 0)) {
        std::cerr << "Failed to enumerate monitors." << std::endl;
        return;
    }
    availableMonitors = monitorsTemp;

    // Panel and main sizer
    wxPanel* panel = new wxPanel(this);
    panel->SetBackgroundColour(wxColour(26, 26, 26)); // light gray
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);

    // Modern title text
    wxStaticText* title = new wxStaticText(panel, wxID_ANY, "Please Select a Monitor to Share");
    title->SetFont(wxFont(18, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    title->SetForegroundColour(wxColour(255, 255, 255));
    
    mainSizer->Add(title, 0, wxALIGN_CENTER | wxTOP | wxBOTTOM, 20);

    // ListBox for monitors
    monitorListBox = new wxListBox(panel, wxID_ANY);
    monitorListBox->SetMinSize(wxSize(550, 250));
    monitorListBox->SetBackgroundColour(wxColour(50, 50, 50));
    monitorListBox->SetForegroundColour(wxColour(255, 255, 255));
    PopulateMonitorList();
    mainSizer->Add(monitorListBox, 0, wxALIGN_CENTER | wxALL, 10);

    // Set sizer and center
    panel->SetSizer(mainSizer);
    Centre();

    monitorListBox->Bind(wxEVT_LISTBOX, &MonitorSelectorWindow::OnSelect, this);
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

        
        wxRect screenRect = wxRect(availableMonitors[index].x, availableMonitors[index].y, availableMonitors[index].width, availableMonitors[index].height);
        FileTransfer* fileTransfer = new FileTransfer(this->server->getAesKey(), FILETRANSFERUDPSERVERSRCPORT, FILETRANSFERTCPSERVERDSTPORT, this->server->getTCPConnection());
        std::thread t(&FileTransfer::startConnection, fileTransfer, this->server->getDstIP(), SERVER);
        t.detach();

        ScreenShareWindow* shareFrame = new ScreenShareWindow(screenRect, server, fileTransfer);
        shareFrame->Start();
    }
}
