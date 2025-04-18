#include "Gui/MainWindow.h"

class MyApp : public wxApp {
public:
    virtual bool OnInit() {
        MainWindow* mainWin = new MainWindow();
        mainWin->Show();
        return true;
    }
};

wxIMPLEMENT_APP(MyApp);

