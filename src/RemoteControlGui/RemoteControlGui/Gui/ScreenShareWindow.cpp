#include "ScreenShareWindow.h"
#include "ControlButtons.h"
wxBEGIN_EVENT_TABLE(ScreenShareWindow, wxFrame)
EVT_PAINT(ScreenShareWindow::OnPaint)
EVT_TIMER(wxID_ANY, ScreenShareWindow::OnTimer)
wxEND_EVENT_TABLE()

ScreenShareWindow::ScreenShareWindow(const wxRect& screenRect, Server* serverObj, FileTransfer* fileTransferObj)
    : wxFrame(nullptr, wxID_ANY, "", screenRect.GetPosition(), screenRect.GetSize(),
        wxFRAME_SHAPED | wxFRAME_NO_TASKBAR | wxSTAY_ON_TOP),
    m_timer(this), server(serverObj)
{
    SetTransparent(40);  // Slight transparency
    SetBackgroundStyle(wxBG_STYLE_PAINT);

#ifdef __WXMSW__
    // Make the frame click-through on Windows
    HWND hwnd = (HWND)GetHWND();
    SetWindowLong(hwnd, GWL_EXSTYLE,
        GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED | WS_EX_TRANSPARENT);
#endif

    ControlButtons* buttons = new ControlButtons(this, screenRect.GetTopLeft() + wxPoint(0, 0), serverObj, fileTransferObj);
    Show();
    m_timer.Start(500); // Change every 500ms
}

ScreenShareWindow::~ScreenShareWindow()
{
    m_timer.Stop();
}

void ScreenShareWindow::Start()
{
    Show();
    m_timer.Start();
    std::thread([this]() {
        this->server->updateChannelData();
    }).detach();
}

void ScreenShareWindow::Stop()
{
    m_timer.Stop();
    Hide();
}

void ScreenShareWindow::OnTimer(wxTimerEvent& event)
{
    m_visibleFrame = !m_visibleFrame;
    Refresh();
}

void ScreenShareWindow::OnPaint(wxPaintEvent& event)
{
    if (!m_visibleFrame) return;

    wxPaintDC dc(this);
    dc.SetBackground(wxBrush(wxColour(0, 0, 0, 0)));
    dc.Clear();

    wxPen pen(*wxGREEN, 17); // Thick green border
    dc.SetPen(pen);
    dc.SetBrush(*wxTRANSPARENT_BRUSH);

    wxSize size = GetClientSize();
    dc.DrawRectangle(0, 0, size.x, size.y);
}
