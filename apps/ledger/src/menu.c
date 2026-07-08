#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"

#include "menu.h"
#include "display.h"

static void app_quit(void) {
    os_sched_exit(-1);
}

void ui_menu_main(void) {
    nbgl_useCaseHomeAndSettings(APPNAME,
                                &ICON_APP_KOKUIN,
                                NULL,
                                INIT_HOME_PAGE,
                                NULL,
                                NULL,
                                NULL,
                                app_quit);
}
