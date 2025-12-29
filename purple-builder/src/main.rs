mod identity;
mod main_window;
mod welcome_window;

use crate::main_window::MainWindow;
use crate::welcome_window::WelcomeWindow;
use gpui::*;
use gpui_component::{ActiveTheme as _, Root, TitleBar, theme};

fn main() {
    let application = Application::new();

    application.run(|cx: &mut App| {
        gpui_component::init(cx);
        // theme::init(cx);

        //WelcomeWindow::new(cx).expect("Could not create WelcomeWindow.");
        MainWindow::new(cx).expect("Could not create MainWindow.");
    });
}
