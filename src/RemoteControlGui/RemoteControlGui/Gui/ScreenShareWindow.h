#include <wx/wx.h>
#include <wx/timer.h>
#include "../Infrastructure/Server.h"
#include "../FileTransmission/FileTransfer.h"

class ScreenShareWindow : public wxFrame
{
public:
    ScreenShareWindow(const wxRect& screenRect, Server* serverObj, FileTransfer* fileTransferObj);
    ~ScreenShareWindow();

    void Start();
    void Stop();

private:
    void OnPaint(wxPaintEvent& event);
    void OnTimer(wxTimerEvent& event);

    wxTimer m_timer;
    bool m_visibleFrame = true;

    Server* server;

    wxDECLARE_EVENT_TABLE();
};