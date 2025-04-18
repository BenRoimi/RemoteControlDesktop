#include <wx/wx.h>

class EnterPasswordWindow : public wxFrame
{
public:
    EnterPasswordWindow(wxWindow* parent);

private:
    wxTextCtrl* passwordInput;
    wxButton* waitConnectionButton;

    void OnWaitConnectionClicked(wxCommandEvent& event);

    wxDECLARE_EVENT_TABLE();
};