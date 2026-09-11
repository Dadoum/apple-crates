mod app;
mod backend;
mod constants;
mod device_selection;
mod domain;
mod ui;

#[cfg(test)]
mod architecture_tests;

use constants::{WINDOW_HEIGHT, WINDOW_WIDTH};
use gpui::{px, size, App, AppContext, Bounds, QuitMode, WindowBounds, WindowOptions};
use log::LevelFilter;
use ui::assets::Assets;
use ui::main_view::SideloaderView;

fn main() {
    init_logging();

    gpui_platform::application()
        .with_assets(Assets)
        .with_quit_mode(QuitMode::LastWindowClosed)
        .run(|cx: &mut App| {
            gpui_component::init(cx);
            #[cfg(target_os = "linux")]
            ui::prompt::install(cx);

            let window_size = size(px(WINDOW_WIDTH), px(WINDOW_HEIGHT));
            let bounds = Bounds::centered(None, window_size, cx);

            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    window_min_size: Some(window_size),
                    is_resizable: true,
                    ..Default::default()
                },
                |window, cx| {
                    window.set_window_title("Super Sideloader");
                    cx.new(|cx| SideloaderView::new(window, cx))
                },
            )
            .expect("failed to open Super Sideloader window");

            cx.activate(true);
        });
}

fn init_logging() {
    let mut builder = env_logger::Builder::new();
    builder
        .filter_module("reqwest", LevelFilter::Info)
        .filter_module("hyper", LevelFilter::Info)
        .filter_module("h2", LevelFilter::Info)
        .filter_module("rustls", LevelFilter::Info)
        .filter_module("elf_loader", LevelFilter::Info);
    builder.parse_default_env();
    builder.init();
}
