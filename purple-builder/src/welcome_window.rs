use crate::identity::*;
use gpui::*;
use gpui_component::button::Button;
use gpui_component::label::Label;
use gpui_component::menu::AppMenuBar;
use gpui_component::{Root, Theme, TitleBar, v_flex};

pub struct WelcomeWindow;

impl WelcomeWindow {
    pub(crate) fn new(cx: &mut App) -> Result<WindowHandle<Root>> {
        let bounds = Bounds::centered(None, size(px(600.), px(400.)), cx);

        let window_options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            is_resizable: false,
            // window_decorations: Some(WindowDecorations::Client),
            // titlebar: Some(TitleBar::title_bar_options()),
            ..Default::default()
        };

        cx.open_window(window_options, |win, cx| {
            let welcome_view = WelcomeView::new();

            let view = cx.new(|_| welcome_view);
            cx.new(|cx| Root::new(view.into(), win, cx))
        })
    }
}

struct WelcomeView {
    // recent_projects: Vec<String>,
}

impl WelcomeView {
    pub(crate) fn new() -> Self {
        Self {
            // recent_projects: vec![
            //     "MyApp".to_string(),
            //     "MyGame".to_string(),
            //     "MyLibrary".to_string(),
            // ],
        }
    }
}

impl Render for WelcomeView {
    fn render(&mut self, win: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        /*
        let titlebar =
            TitleBar::new()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .child(AppMenuBar::new(win, cx))
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_end()
                        .gap_2()
                        .child(win.window_title())
                        // .child(Button::new("github")) // .icon(IconName::GitHub))
                        // .child(Button::new("notifications")) // .icon(IconName::Bell))
                );

        // let state: Self = cx.;

        /*
        // Create editor state
        let editor_state = cx.new(|cx| {
            let mut state = EditorState::new(cx);
            state.set_language(Language::Sql, cx);
            state.set_content("SELECT * FROM users;", cx);
            state
        }); // */ // */

        // Render editor

        v_flex()
            .size_full()
            // .child(
            //     div()
            //         .child(
            //             AppMenuBar::new(win, cx)
            //         )
            // )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .size_full()
                    .p_4()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .size_full()
                            .m_4()
                            .gap_4()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .text_center()
                                    .child(
                                        Label::new(format!("Welcome to {}", APP_NAME))
                                            .text_xl()
                                            .font_weight(FontWeight::BOLD),
                                    )
                                    .child(
                                        Label::new("Version 1.0.0")
                                            .text_sm()
                                            .text_color(rgb(0x666666)),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(
                                        Button::new("create_project")
                                            .text_left()
                                            .label("Create New Project")
                                            .on_click(|_, _, _| {
                                                println!("Create New Project clicked")
                                            }),
                                    )
                                    .child(
                                        Button::new("open_project")
                                            .text_left()
                                            .label("Open Existing Project")
                                            .on_click(|_, _, _| {
                                                println!("Open Existing Project clicked")
                                            }),
                                    )
                                    .child(
                                        Button::new("clone_project")
                                            .text_left()
                                            .label("Clone Repository")
                                            .on_click(|_, _, _| {
                                                println!("Clone Repository clicked")
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .m_4()
                            .child(
                                Label::new("Recent Projects")
                                    .text_lg()
                                    .font_weight(FontWeight::SEMIBOLD),
                            )
                            .child(
                                div().flex().flex_col().gap_1(), // .children(
                                                                 //     state.recent_projects.iter().map(|project| {
                                                                 //         div()
                                                                 //             .p_2()
                                                                 //             .rounded_md()
                                                                 //             .hover(|s| s.bg(rgb(0xe5e5e5)))
                                                                 //             .child(
                                                                 //                 Label::new(project)
                                                                 //                     .size_full()
                                                                 //             )
                                                                 //     })
                                                                 // )
                            ),
                    ),
            )
    }
}
