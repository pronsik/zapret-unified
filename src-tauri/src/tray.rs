//! Значок в системном трее. Окно по крестику не закрывается, а прячется — приложение
//! продолжает работать в фоне (VPN, zapret, tg-ws-proxy), а значок остаётся среди «скрытых
//! значков» Windows. Правый клик — меню, левый — показать окно.

use crate::{
    connect_inner, disconnect_inner, set_tgproxy_enabled, set_zapret_enabled, shutdown_services,
    AppState,
};
use std::time::Duration;
use tauri::{
    AppHandle, CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem,
};

pub fn build() -> SystemTray {
    let menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("show", "Показать приложение"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("vpn", "Подключить VPN"))
        .add_item(CustomMenuItem::new("zapret", "Выключить zapret"))
        .add_item(CustomMenuItem::new("tgproxy", "Включить tg-ws-proxy"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit", "Выйти"));
    SystemTray::new().with_menu(menu)
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

pub fn on_event(app: &AppHandle, event: SystemTrayEvent) {
    match event {
        SystemTrayEvent::LeftClick { .. } | SystemTrayEvent::DoubleClick { .. } => {
            show_main_window(app)
        }
        SystemTrayEvent::MenuItemClick { id, .. } => on_menu(app, id),
        _ => {}
    }
}

fn on_menu(app: &AppHandle, id: String) {
    match id.as_str() {
        "show" => show_main_window(app),
        "quit" => quit(app),
        "vpn" | "zapret" | "tgproxy" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                run_action(&app, &id).await;
                sync_titles(&app);
            });
        }
        _ => {}
    }
}

/// Полный выход (в отличие от закрытия окна). Остановка VPN-ядер идёт корректно, с откатом
/// TUN-маршрутов, и занимает несколько секунд — поэтому окно прячется сразу, а завершение
/// происходит в отдельном потоке.
fn quit(app: &AppHandle) {
    if let Some(w) = app.get_window("main") {
        let _ = w.hide();
    }
    let app = app.clone();
    std::thread::spawn(move || {
        if let Some(st) = app.try_state::<AppState>() {
            shutdown_services(st.inner());
        }
        app.exit(0);
    });
}

async fn run_action(app: &AppHandle, id: &str) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let st = state.inner();

    let result: Result<(), String> = match id {
        "vpn" => toggle_vpn(app, st).await,
        "zapret" => {
            let on = st.config.lock().unwrap().zapret_enabled;
            set_zapret_enabled(st, !on).await.map(|_| ())
        }
        "tgproxy" => {
            let on = st.config.lock().unwrap().tgproxy_enabled;
            set_tgproxy_enabled(st, !on).map(|_| ())
        }
        _ => Ok(()),
    };

    // Из трея ошибку некуда показать, кроме самого окна: открываем его и шлём текст ошибки.
    if let Err(e) = result {
        let _ = app.emit_all("tray-error", e);
        show_main_window(app);
    }
}

async fn toggle_vpn(app: &AppHandle, st: &AppState) -> Result<(), String> {
    if st.vpn.is_running() {
        disconnect_inner(st).await?;
        return Ok(());
    }
    // Подключаемся к последнему использованному серверу, а если такого нет — к первому в списке.
    let id = {
        let cfg = st.config.lock().unwrap();
        let id = cfg
            .vpn_active_id
            .clone()
            .or_else(|| cfg.vpn_servers.first().map(|s| s.id.clone()));
        id
    }
    .ok_or("нет ни одного сервера — добавьте подписку или сервер")?;
    connect_inner(app, st, id, false).await?;
    Ok(())
}

/// Состояние для надписей пунктов: (VPN запущен, zapret включён, tgproxy включён, есть серверы).
fn snapshot(app: &AppHandle) -> Option<(bool, bool, bool, bool)> {
    let state = app.try_state::<AppState>()?;
    let st = state.inner();
    let vpn_on = st.vpn.is_running();
    let cfg = st.config.lock().unwrap();
    Some((
        vpn_on,
        cfg.zapret_enabled,
        cfg.tgproxy_enabled,
        !cfg.vpn_servers.is_empty(),
    ))
}

/// Надписи пунктов меню отражают текущее состояние: «Подключить VPN» / «Отключить VPN» и т.д.
pub fn sync_titles(app: &AppHandle) {
    let Some((vpn_on, zapret_on, tg_on, has_servers)) = snapshot(app) else {
        return;
    };
    apply_titles(app, (vpn_on, zapret_on, tg_on, has_servers));
}

fn apply_titles(app: &AppHandle, (vpn_on, zapret_on, tg_on, has_servers): (bool, bool, bool, bool)) {
    let tray = app.tray_handle();
    let vpn = tray.get_item("vpn");
    let _ = vpn.set_title(if vpn_on { "Отключить VPN" } else { "Подключить VPN" });
    let _ = vpn.set_enabled(vpn_on || has_servers);
    let _ = tray
        .get_item("zapret")
        .set_title(if zapret_on { "Выключить zapret" } else { "Включить zapret" });
    let _ = tray
        .get_item("tgproxy")
        .set_title(if tg_on { "Выключить tg-ws-proxy" } else { "Включить tg-ws-proxy" });
}

/// Раз в пару секунд подтягивает состояние в меню (подключение могло произойти из окна, из
/// автообновления или упасть само). Надписи меняются только при реальном изменении состояния —
/// иначе обновление пунктов могло бы мигать у открытого меню.
pub fn spawn_sync_loop(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last: Option<(bool, bool, bool, bool)> = None;
        loop {
            let cur = snapshot(&app);
            if cur.is_some() && cur != last {
                if let Some(c) = cur {
                    apply_titles(&app, c);
                }
                last = cur;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}
