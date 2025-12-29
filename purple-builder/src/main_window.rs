use gpui::{
    App, AppContext, Bounds, Context, Entity, IntoElement, ParentElement, Render, Styled, Window,
    WindowBounds, WindowHandle, WindowKind, WindowOptions, div, px, size,
};
use gpui_component::dock::{DockArea, DockAreaState};
use gpui_component::menu::AppMenuBar;
use gpui_component::{Root, StyledExt};

pub struct MainWindow;

impl MainWindow {
    pub(crate) fn new(cx: &mut App) -> anyhow::Result<WindowHandle<Root>> {
        let bounds = Bounds::centered(None, size(px(600.), px(400.)), cx);

        let window_options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            #[cfg(not(target_os = "linux"))]
            titlebar: Some(gpui_component::TitleBar::title_bar_options()),
            window_min_size: Some(gpui::Size {
                width: px(640.),
                height: px(480.),
            }),
            #[cfg(target_os = "linux")]
            window_background: gpui::WindowBackgroundAppearance::Transparent,
            #[cfg(target_os = "linux")]
            window_decorations: Some(gpui::WindowDecorations::Client),
            kind: WindowKind::Normal,
            ..Default::default()
        };

        cx.open_window(window_options, |win, cx| {
            let welcome_view = MainView::new();

            let view = cx.new(|_| welcome_view);
            cx.new(|cx| Root::new(view.into(), win, cx))
        })
    }
}

struct MainView {
    title_bar: Entity<AppMenuBar>,
    dock_area: Entity<DockArea>,
    last_layout_state: Option<DockAreaState>,
}

impl MainView {
    fn new() -> Self {
        Self {}
    }
}

impl Render for MainView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .v_flex()
            .size_full()
            .child(div().flex().items_center().justify_center().child("Ready"))
    }
}
