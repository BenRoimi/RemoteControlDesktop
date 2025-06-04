#include <wx/wx.h>

class EnterPasswordWindow : public wxFrame
{
public:
    EnterPasswordWindow(wxWindow* parent);

private:
    wxTextCtrl* passwordInput;
    wxButton* waitConnectionButton;
    wxButton* togglePasswordBtn;
    wxButton* backButton;            // New back button
    bool passwordVisible;

    void OnWaitConnectionClicked(wxCommandEvent& event);
    void OnTogglePassword(wxCommandEvent& event);
    void OnBackClicked(wxCommandEvent& event);  // Handler for back button

    wxDECLARE_EVENT_TABLE();
};
