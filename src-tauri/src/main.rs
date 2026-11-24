#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bootstrap;
mod config;
mod instance;
mod lists;
mod proc_util;
mod process_monitor;
mod status;
mod strategies;
mod tgproxy_manager;
mod tray;
mod tun_mode;
mod updater;
mod vpn_manager;
mod zapret_manager;

use config::AppConfig;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::Manager;
use tgproxy_manager::TgProxyManager;
use vpn_manager::VpnManager;
use zapret_manager::ZapretManager;

struct AppState {
    config: Mutex<AppConfig>,
    zapret: Arc<ZapretManager>,
    tgproxy: Arc<TgProxyManager>,
    vpn: Arc<VpnManager>,
    resources_dir: PathBuf,
    /// Растёт при каждом отключении VPN. connect_inner запоминает значение на старте и, если оно
    /// изменилось, пока докачивались ядра / считались маршруты / запускался процесс, понимает, что
    /// пользователь уже нажал "отключить", и не включает VPN обратно.
    vpn_epoch: std::sync::atomic::AtomicU64,
    /// Unix-секунды, когда VPN был успешно запущен; None — не подключён.
    vpn_started: Mutex<Option<i64>>,
}

#[tauri::command]
fn get_config(state: tauri::State<AppState>) -> AppConfig {
    state.config.lock().unwrap().clone()
}

#[tauri::command]
fn add_whitelisted_app(state: tauri::State<AppState>, exe_name: String) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    config::add_app(&mut cfg, exe_name).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn remove_whitelisted_app(state: tauri::State<AppState>, exe_name: String) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    config::remove_app(&mut cfg, &exe_name).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn set_strategy(state: tauri::State<AppState>, strategy: String) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    cfg.strategy = strategy;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn list_running_apps() -> Vec<String> {
    process_monitor::list_running_exe_names()
}

#[tauri::command]
fn available_strategies(state: tauri::State<AppState>) -> Vec<String> {
    let zapret_dir = state.resources_dir.join("zapret");
    strategies::list_strategies(&zapret_dir)
}

#[tauri::command]
fn is_zapret_running(state: tauri::State<AppState>) -> bool {
    state.zapret.is_running()
}

/// Остановка обхода вместе с выгрузкой драйвера WinDivert. Выполняется в рабочем потоке: выгрузка
/// драйвера запускает sc.exe, а синхронные команды Tauri 1.x идут в потоке окна и подвесили бы его.
#[tauri::command]
async fn stop_zapret(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let z = state.zapret.clone();
    tauri::async_runtime::spawn_blocking(move || z.stop())
        .await
        .map_err(|e| e.to_string())
}

/// Проверка одной стратегии (аналог "Run Test" из service.bat оригинального репозитория):
/// временно запускает winws.exe с её аргументами, PID-привязанный к нам же самим, и
/// дёргает тестовые домены. Останавливает обычный автозапуск на время теста и не
/// восстанавливает его автоматически — следующий тик watch_loop сам разберётся.
#[tauri::command]
async fn zapret_test_strategy(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    strategy: String,
) -> Result<Vec<zapret_manager::TestTarget>, String> {
    let zapret_dir = state.resources_dir.join("zapret");
    let bin_dir = zapret_dir.join("bin");
    let lists_dir = zapret_dir.join("lists");
    let args = strategies::build_args(&strategy, &zapret_dir, &bin_dir, &lists_dir)
        .map_err(|e| e.to_string())?;
    let name = strategy.clone();
    let app2 = app.clone();
    let cb = move |idx: usize, st: Option<bool>| {
        let state = match st { None => "run", Some(true) => "ok", Some(false) => "fail" };
        let _ = app2.emit_all("strategy-probe", serde_json::json!({ "strategy": name, "idx": idx, "state": state }));
    };
    Ok(state.zapret.test_strategy(&args, &cb).await)
}

/// Прогоняет test_strategy по очереди для ВСЕХ доступных стратегий и шлёт прогресс
/// через событие "strategy-test-progress" после каждой — чтобы UI показывал результаты
/// по мере готовности, а не ждал минуту тишины на весь список сразу.
#[tauri::command]
async fn zapret_test_all_strategies(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<zapret_manager::StrategyTestResult>, String> {
    let zapret_dir = state.resources_dir.join("zapret");
    let bin_dir = zapret_dir.join("bin");
    let lists_dir = zapret_dir.join("lists");
    let strategy_names = strategies::list_strategies(&zapret_dir);

    let mut all = Vec::with_capacity(strategy_names.len());
    for strategy in strategy_names {
        let name = strategy.clone();
        let app2 = app.clone();
        let cb = move |idx: usize, st: Option<bool>| {
            let state = match st { None => "run", Some(true) => "ok", Some(false) => "fail" };
            let _ = app2.emit_all("strategy-probe", serde_json::json!({ "strategy": name, "idx": idx, "state": state }));
        };
        let targets = match strategies::build_args(&strategy, &zapret_dir, &bin_dir, &lists_dir) {
            Ok(args) => state.zapret.test_strategy(&args, &cb).await,
            Err(e) => vec![zapret_manager::TestTarget {
                name: "winws.exe".into(),
                ok: false,
                error: Some(e.to_string()),
            }],
        };
        let result = zapret_manager::StrategyTestResult { strategy, targets };
        let _ = app.emit_all("strategy-test-progress", &result);
        all.push(result);
    }
    Ok(all)
}

// ---------------------------------------------------------------------------------------
// Настройки tg-ws-proxy
// ---------------------------------------------------------------------------------------

/// Текущие настройки. Если секрета ещё нет — он создаётся и сохраняется сразу, чтобы пользователь
/// видел именно тот секрет, с которым прокси будет запущен.
#[tauri::command]
fn tgproxy_get_settings(state: tauri::State<AppState>) -> Result<config::TgProxySettings, String> {
    let mut cfg = state.config.lock().unwrap();
    if cfg.tgproxy_settings.secret.trim().is_empty() {
        cfg.tgproxy_settings.secret = tgproxy_manager::random_secret();
        config::save(&cfg).map_err(|e| e.to_string())?;
        state.tgproxy.set_args(tgproxy_manager::build_args(&cfg.tgproxy_settings));
    }
    Ok(cfg.tgproxy_settings.clone())
}

/// Значения по умолчанию (секрет сохраняется — сброс настроек не должен ломать ссылку).
#[tauri::command]
fn tgproxy_default_settings(state: tauri::State<AppState>) -> config::TgProxySettings {
    let mut d = config::TgProxySettings::default();
    d.secret = state.config.lock().unwrap().tgproxy_settings.secret.clone();
    d
}

#[tauri::command]
fn tgproxy_new_secret() -> String {
    tgproxy_manager::random_secret()
}

/// Командная строка, которая получится из настроек, — для предпросмотра в редакторе.
#[tauri::command]
fn tgproxy_preview_args(settings: config::TgProxySettings) -> Result<Vec<String>, String> {
    let mut s = settings;
    tgproxy_manager::normalize_settings(&mut s)?;
    Ok(tgproxy_manager::build_args(&s))
}

/// Сохраняет настройки и (по желанию) перезапускает работающий прокси с новыми аргументами.
#[tauri::command]
async fn tgproxy_save_settings(
    state: tauri::State<'_, AppState>,
    settings: config::TgProxySettings,
    restart: bool,
) -> Result<config::TgProxySettings, String> {
    let mut s = settings;
    tgproxy_manager::normalize_settings(&mut s)?;
    if s.secret.is_empty() {
        s.secret = tgproxy_manager::random_secret();
    }
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.tgproxy_settings = s.clone();
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    state.tgproxy.set_args(tgproxy_manager::build_args(&s));

    if restart && state.tgproxy.is_running() {
        let tg = state.tgproxy.clone();
        tauri::async_runtime::spawn_blocking(move || tg.start())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
    }
    Ok(s)
}

/// Профили маршрутизации: сохранённые наборы правил и адресов в обход. Применение подменяет
/// текущие правила туннеля; подключённый VPN нужно переподключить, чтобы они вступили в силу.
#[tauri::command]
fn profile_save(state: tauri::State<AppState>, name: String) -> Result<AppConfig, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("укажите название профиля".into());
    }
    let mut cfg = state.config.lock().unwrap();
    if cfg.profiles.iter().any(|p| p.name == name) {
        return Err("профиль с таким названием уже есть".into());
    }
    let profile = config::RoutingProfile {
        id: vpn_manager::new_id("prof"),
        name,
        routing_rules: cfg.tunnel.routing_rules.clone(),
        bypass_addresses: cfg.tunnel.bypass_addresses.clone(),
    };
    cfg.profiles.push(profile);
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn profile_apply(state: tauri::State<AppState>, id: String) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    let profile = cfg
        .profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .or_else(|| config::builtin_profiles().into_iter().find(|p| p.id == id))
        .ok_or("профиль не найден")?;
    cfg.tunnel.routing_rules = profile.routing_rules;
    cfg.tunnel.bypass_addresses = profile.bypass_addresses;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn profile_delete(state: tauri::State<AppState>, id: String) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    cfg.profiles.retain(|p| p.id != id);
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

/// Время начала текущего подключения (unix-секунды) — для счётчика в интерфейсе.
#[tauri::command]
fn vpn_started_at(state: tauri::State<AppState>) -> Option<i64> {
    *state.vpn_started.lock().unwrap()
}

/// Встроенные профили для интерфейса.
#[tauri::command]
fn profile_presets() -> Vec<config::RoutingProfile> {
    config::builtin_profiles()
}

/// Репозитории, из которых приложение скачивает компоненты. Интерфейс строит из них кнопки
/// «Официальный источник» — адрес берётся из тех же констант, что использует апдейтер,
/// поэтому ссылка не может разойтись с тем, откуда реально приходят файлы.
#[tauri::command]
fn component_sources() -> serde_json::Value {
    serde_json::json!({
        "zapret": updater::ZAPRET_REPO,
        "tgproxy": updater::TGPROXY_REPO,
        "xray": updater::XRAY_REPO,
        "singbox": "SagerNet/sing-box",
        "tun2proxy": "tun2proxy/tun2proxy",
    })
}

/// Состояние обхода с причиной ("ждёт whitelist", "ошибка стратегии: ...", "winws.exe
/// завершился с кодом N: ...", "работает") — чтобы интерфейс не гадал, а показывал.
#[tauri::command]
fn zapret_status(state: tauri::State<AppState>) -> zapret_manager::ZapretStatus {
    state.zapret.status()
}

/// Мастер-переключатель обхода DPI из UI. При выключении winws.exe останавливается
/// немедленно и не запускается заново, пока пользователь не включит обратно —
/// даже если среди процессов есть whitelisted-приложения.
/// Включает/выключает обход DPI. Общая логика для команды интерфейса и меню трея.
async fn set_zapret_enabled(st: &AppState, enable: bool) -> Result<AppConfig, String> {
    {
        let mut cfg = st.config.lock().unwrap();
        cfg.zapret_enabled = enable;
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    // Выключение останавливает winws.exe и выгружает драйвер WinDivert (sc.exe) — не в потоке окна.
    let z = st.zapret.clone();
    tauri::async_runtime::spawn_blocking(move || z.set_user_enabled(enable))
        .await
        .map_err(|e| e.to_string())?;
    Ok(st.config.lock().unwrap().clone())
}

fn set_tgproxy_enabled(st: &AppState, enable: bool) -> Result<AppConfig, String> {
    {
        let mut cfg = st.config.lock().unwrap();
        cfg.tgproxy_enabled = enable;
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    if enable {
        st.tgproxy.start().map_err(|e| e.to_string())?;
    } else {
        st.tgproxy.stop();
    }
    Ok(st.config.lock().unwrap().clone())
}

#[tauri::command]
async fn toggle_zapret(
    state: tauri::State<'_, AppState>,
    enable: bool,
) -> Result<AppConfig, String> {
    set_zapret_enabled(state.inner(), enable).await
}

/// Аналог "Remove Services" из service.bat: выключает обход, завершает все winws.exe, удаляет
/// службу zapret (если её ставили через service.bat) и выгружает драйвер WinDivert. Раньше для
/// этого приходилось открывать service.bat руками. Возвращает отчёт по шагам.
#[tauri::command]
async fn zapret_remove_services(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    let st = state.inner();
    {
        let mut cfg = st.config.lock().unwrap();
        cfg.zapret_enabled = false;
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    let z = st.zapret.clone();
    tauri::async_runtime::spawn_blocking(move || z.remove_services())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn toggle_tgproxy(state: tauri::State<AppState>, enable: bool) -> Result<AppConfig, String> {
    set_tgproxy_enabled(state.inner(), enable)
}

/// Останавливает всё, что приложение запустило: VPN-ядра (корректно, с откатом TUN-маршрутов),
/// системный прокси, winws и tg-ws-proxy. Вызывается при выходе — и из меню трея, и при
/// обычном завершении.
fn shutdown_services(st: &AppState) {
    st.vpn.stop();
    let _ = vpn_manager::set_system_proxy(false);
    st.zapret.stop();
    st.tgproxy.stop();
}

#[tauri::command]
async fn check_status() -> Vec<status::ServiceStatus> {
    status::check_all().await
}

#[tauri::command]
async fn check_for_updates(state: tauri::State<'_, AppState>) -> Result<Vec<updater::UpdateCheck>, String> {
    let (zapret_ver, tgproxy_ver, xray_ver) = {
        let cfg = state.config.lock().unwrap();
        (cfg.zapret_version.clone(), cfg.tgproxy_version.clone(), cfg.xray_version.clone())
    };

    let zapret_check = updater::check_zapret(zapret_ver.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    let tgproxy_check = updater::check_tgproxy(tgproxy_ver.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    let xray_check = updater::check_xray(xray_ver.as_deref())
        .await
        .map_err(|e| e.to_string())?;

    {
        let mut cfg = state.config.lock().unwrap();
        cfg.last_checked = Some(chrono::Utc::now().to_rfc3339());
        let _ = config::save(&cfg);
    }

    Ok(vec![zapret_check, tgproxy_check, xray_check])
}

/// component: "zapret" | "tgproxy". Скачивает и подменяет файлы, обновляет
/// сохранённую версию в конфиге. Для zapret на время замены ставит winws.exe на паузу.
#[tauri::command]
async fn apply_update(
    state: tauri::State<'_, AppState>,
    component: String,
) -> Result<AppConfig, String> {
    let resources_dir = state.resources_dir.clone();

    match component.as_str() {
        "zapret" => {
            let current = state.config.lock().unwrap().zapret_version.clone();
            let check = updater::check_zapret(current.as_deref())
                .await
                .map_err(|e| e.to_string())?;

            state.zapret.pause_for_update();
            let result = updater::apply_zapret_update(&check, &resources_dir).await;
            state.zapret.resume_after_update();
            result.map_err(|e| e.to_string())?;

            let mut cfg = state.config.lock().unwrap();
            cfg.zapret_version = Some(check.latest_version);
            config::save(&cfg).map_err(|e| e.to_string())?;
            Ok(cfg.clone())
        }
        "tgproxy" => {
            let current = state.config.lock().unwrap().tgproxy_version.clone();
            let check = updater::check_tgproxy(current.as_deref())
                .await
                .map_err(|e| e.to_string())?;

            let was_running = state.tgproxy.is_running();
            state.tgproxy.stop();
            let result = updater::apply_tgproxy_update(&check, &resources_dir).await;
            if was_running {
                let _ = state.tgproxy.start();
            }
            result.map_err(|e| e.to_string())?;

            let mut cfg = state.config.lock().unwrap();
            cfg.tgproxy_version = Some(check.latest_version);
            config::save(&cfg).map_err(|e| e.to_string())?;
            Ok(cfg.clone())
        }
        "xray" => {
            let current = state.config.lock().unwrap().xray_version.clone();
            let check = updater::check_xray(current.as_deref())
                .await
                .map_err(|e| e.to_string())?;

            let (active_id, tunnel) = {
                let cfg = state.config.lock().unwrap();
                (cfg.vpn_active_id.clone(), cfg.tunnel.clone())
            };
            state.vpn.stop();
            let result = updater::apply_xray_update(&check, &resources_dir).await;
            result.map_err(|e| e.to_string())?;

            if let Some(id) = active_id {
                let server = state
                    .config
                    .lock()
                    .unwrap()
                    .vpn_servers
                    .iter()
                    .find(|s| s.id == id)
                    .cloned();
                if let Some(server) = server {
                    let _ = state.vpn.connect(&server, &tunnel);
                }
            }

            let mut cfg = state.config.lock().unwrap();
            cfg.xray_version = Some(check.latest_version);
            config::save(&cfg).map_err(|e| e.to_string())?;
            Ok(cfg.clone())
        }
        other => Err(format!("неизвестный компонент: {other}")),
    }
}

#[tauri::command]
fn toggle_auto_update(state: tauri::State<AppState>, enable: bool) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    cfg.auto_update = enable;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn vpn_add_server(state: tauri::State<AppState>, link: String) -> Result<AppConfig, String> {
    let text = link.trim();
    // Одна ссылка (vless://…) или JSON-конфиг xray — их может быть несколько.
    let servers = if text.starts_with('{') || text.starts_with('[') {
        vpn_manager::parse_json_servers(text)?
    } else {
        vec![vpn_manager::parse_link(text)?]
    };
    let mut cfg = state.config.lock().unwrap();
    for server in servers {
        config::add_vpn_server(&mut cfg, server).map_err(|e| e.to_string())?;
    }
    Ok(cfg.clone())
}

#[tauri::command]
fn vpn_remove_server(state: tauri::State<AppState>, id: String) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    config::remove_vpn_server(&mut cfg, &id).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

/// Общая логика подключения для vpn_connect / vpn_set_mode / vpn_recalibrate:
/// докачать нужные ядра -> (адаптивный режим) откалибровать маршруты -> привязать zapret
/// к физическому интерфейсу -> запустить -> выставить/снять системный прокси.
async fn connect_inner(
    app: &tauri::AppHandle,
    st: &AppState,
    id: String,
    force_recalibrate: bool,
) -> Result<AppConfig, String> {
    let epoch = st.vpn_epoch.load(std::sync::atomic::Ordering::SeqCst);
    let (server, tunnel, mode_str) = {
        let cfg = st.config.lock().unwrap();
        let server = cfg
            .vpn_servers
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .ok_or("сервер не найден в списке")?;
        (server, cfg.tunnel.clone(), cfg.vpn_mode.clone())
    };
    let mode = tun_mode::VpnMode::parse(&mode_str);
    let resources_dir = st.resources_dir.clone();

    let app2 = app.clone();
    let report = move |msg: &str| {
        let _ = app2.emit_all("vpn-progress", msg.to_string());
    };

    tun_mode::ensure_cores(&resources_dir, mode, &report).await?;

    if mode == tun_mode::VpnMode::Adaptive {
        report("калибрую маршруты: проверяю, что открывается напрямую…");
        let plan = tun_mode::calibrate(&resources_dir, force_recalibrate).await;
        st.vpn.set_plan(Some(plan));
    }

    // Привязку winws к физической сетевой карте нужно определять ДО подъёма TUN —
    // потом маршрут по умолчанию уже будет указывать на виртуальный адаптер.
    if mode.is_tun() {
        st.zapret.set_iface_pin(tun_mode::detect_physical_ifindex());
    } else {
        st.zapret.set_iface_pin(None);
    }

    // Пока докачивались ядра и считались маршруты, пользователь мог нажать "отключить" — тогда
    // подключение отменяется молча, а не включает VPN обратно.
    if st.vpn_epoch.load(std::sync::atomic::Ordering::SeqCst) != epoch {
        return Ok(st.config.lock().unwrap().clone());
    }

    report("запускаю…");
    st.vpn.set_mode(mode);
    let vpn = st.vpn.clone();
    tauri::async_runtime::spawn_blocking(move || vpn.connect(&server, &tunnel))
        .await
        .map_err(|e| e.to_string())??;

    // То же самое, если "отключить" нажали уже во время запуска: VpnManager сериализует операции,
    // так что отключение остановит только что запущенный процесс, а здесь нельзя вернуть
    // системный прокси и пометить сервер активным.
    if st.vpn_epoch.load(std::sync::atomic::Ordering::SeqCst) != epoch {
        let _ = vpn_manager::set_system_proxy(false);
        return Ok(st.config.lock().unwrap().clone());
    }

    *st.vpn_started.lock().unwrap() = Some(now_unix());

    // Системный прокси нужен только в proxy-режиме: в TUN-режимах весь трафик и так идёт
    // через адаптер, а прокси в реестре только мешал бы (двойная обработка).
    if mode == tun_mode::VpnMode::Proxy {
        if let Err(e) = vpn_manager::set_system_proxy(true) {
            eprintln!("[vpn] не удалось включить системный прокси: {e}");
        }
    } else {
        let _ = vpn_manager::set_system_proxy(false);
    }

    let mut cfg = st.config.lock().unwrap();
    cfg.vpn_active_id = Some(id);
    cfg.vpn_system_proxy = mode == tun_mode::VpnMode::Proxy;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

async fn disconnect_inner(st: &AppState) -> Result<AppConfig, String> {
    // Сначала отменяем подключения, которые ещё не дошли до запуска (см. vpn_epoch)...
    st.vpn_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    *st.vpn_started.lock().unwrap() = None;
    // ...затем останавливаем то, что уже запущено (stop() дождётся идущего connect()).
    let vpn = st.vpn.clone();
    tauri::async_runtime::spawn_blocking(move || vpn.stop())
        .await
        .map_err(|e| e.to_string())?;
    let _ = vpn_manager::set_system_proxy(false);
    st.zapret.set_iface_pin(None);

    let mut cfg = st.config.lock().unwrap();
    cfg.vpn_active_id = None;
    cfg.vpn_system_proxy = false;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
async fn vpn_connect(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<AppConfig, String> {
    connect_inner(&app, state.inner(), id, false).await
}

#[tauri::command]
async fn vpn_disconnect(state: tauri::State<'_, AppState>) -> Result<AppConfig, String> {
    disconnect_inner(state.inner()).await
}

/// Смена режима VPN: докачивает нужные ядра (sing-box / tun2proxy / wintun) при первом
/// выборе режима и, если VPN был подключён, переподключает его уже в новом режиме.
#[tauri::command]
async fn vpn_set_mode(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mode: String,
) -> Result<AppConfig, String> {
    let m = tun_mode::VpnMode::parse(&mode);
    let mode_str = match m {
        tun_mode::VpnMode::Proxy => "proxy",
        tun_mode::VpnMode::XrayTun => "xray-tun",
        tun_mode::VpnMode::SingBox => "singbox",
        tun_mode::VpnMode::Tun2Proxy => "tun2proxy",
        tun_mode::VpnMode::Adaptive => "adaptive",
    };
    let st = state.inner();

    let app2 = app.clone();
    let report = move |msg: &str| {
        let _ = app2.emit_all("vpn-progress", msg.to_string());
    };
    tun_mode::ensure_cores(&st.resources_dir, m, &report).await?;

    let reconnect_id = if st.vpn.is_running() {
        st.config.lock().unwrap().vpn_active_id.clone()
    } else {
        None
    };
    if reconnect_id.is_some() {
        disconnect_inner(st).await?;
    }

    {
        let mut cfg = st.config.lock().unwrap();
        cfg.vpn_mode = mode_str.to_string();
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    st.vpn.set_mode(m);

    match reconnect_id {
        Some(id) => connect_inner(&app, st, id, false).await,
        None => Ok(st.config.lock().unwrap().clone()),
    }
}

/// Текущий адаптивный план (сколько доменов пошло напрямую / через прокси) — для показа в UI.
#[tauri::command]
fn vpn_get_plan(state: tauri::State<AppState>) -> Option<tun_mode::AdaptivePlan> {
    state.vpn.plan()
}

/// Принудительная перекалибровка адаптивных маршрутов; если VPN подключён в адаптивном
/// режиме — сразу переподключает его с новым планом.
#[tauri::command]
async fn vpn_recalibrate(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<tun_mode::AdaptivePlan, String> {
    let st = state.inner();
    let active = if st.vpn.is_running() && st.vpn.mode() == tun_mode::VpnMode::Adaptive {
        st.config.lock().unwrap().vpn_active_id.clone()
    } else {
        None
    };

    if let Some(id) = active {
        disconnect_inner(st).await?;
        connect_inner(&app, st, id, true).await?;
    } else {
        let plan = tun_mode::calibrate(&st.resources_dir, true).await;
        st.vpn.set_plan(Some(plan));
    }
    st.vpn.plan().ok_or_else(|| "план не построен".to_string())
}

#[tauri::command]
fn vpn_is_connected(state: tauri::State<AppState>) -> bool {
    state.vpn.is_running()
}

#[tauri::command]
fn vpn_toggle_system_proxy(state: tauri::State<AppState>, enable: bool) -> Result<AppConfig, String> {
    // Прокси в реестре имеет смысл включать, только пока реально поднят локальный
    // socks/http listener xray-core — иначе система укажет на порт, который никто не слушает.
    if enable && !state.vpn.is_running() {
        return Err("сначала подключитесь к серверу".into());
    }
    vpn_manager::set_system_proxy(enable).map_err(|e| e.to_string())?;

    let mut cfg = state.config.lock().unwrap();
    cfg.vpn_system_proxy = enable;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

/// Применяет изменённые настройки туннеля к уже поднятому соединению: если VPN сейчас
/// подключён, перезапускает xray.exe с новым config.json (иначе изменения подхватятся
/// только при следующем connect).
fn reconnect_if_active(state: &AppState) {
    let (active_id, tunnel) = {
        let cfg = state.config.lock().unwrap();
        (cfg.vpn_active_id.clone(), cfg.tunnel.clone())
    };
    if let Some(id) = active_id {
        if state.vpn.is_running() {
            let server = state
                .config
                .lock()
                .unwrap()
                .vpn_servers
                .iter()
                .find(|s| s.id == id)
                .cloned();
            if let Some(server) = server {
                let _ = state.vpn.connect(&server, &tunnel);
            }
        }
    }
}

#[tauri::command]
fn vpn_set_fragment(
    state: tauri::State<AppState>,
    enabled: bool,
    packets: String,
    length: String,
    interval: String,
) -> Result<AppConfig, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.tunnel.fragment = config::FragmentSettings { enabled, packets, length, interval };
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_set_mux(state: tauri::State<AppState>, enabled: bool, concurrency: u32) -> Result<AppConfig, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.tunnel.mux = config::MuxSettings { enabled, concurrency };
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_set_dns(state: tauri::State<AppState>, mode: String, servers: Vec<String>) -> Result<AppConfig, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.tunnel.dns = config::DnsSettings { mode, servers };
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_add_routing_rule(state: tauri::State<AppState>, value: String, action: String) -> Result<AppConfig, String> {
    let rule = config::RoutingRule {
        id: format!("rule-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()),
        value,
        action,
    };
    {
        let mut cfg = state.config.lock().unwrap();
        config::add_routing_rule(&mut cfg, rule).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_remove_routing_rule(state: tauri::State<AppState>, id: String) -> Result<AppConfig, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        config::remove_routing_rule(&mut cfg, &id).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_set_per_app(
    state: tauri::State<AppState>,
    enabled: bool,
    mode: String,
    apps: Vec<String>,
) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    cfg.tunnel.per_app = config::PerAppSettings { enabled, mode, apps };
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

/// Отдельная команда, а не автоматика: перезапуск приложений с новыми флагами — заметное
/// действие (закрывает и переоткрывает браузер/Discord), пользователь должен явно нажать.
#[tauri::command]
fn vpn_apply_per_app(state: tauri::State<AppState>) -> Result<(), String> {
    let settings = state.config.lock().unwrap().tunnel.per_app.clone();
    vpn_manager::apply_per_app(&settings)
}

#[tauri::command]
fn vpn_set_sniffing(state: tauri::State<AppState>, enabled: bool) -> Result<AppConfig, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.tunnel.sniffing_enabled = enabled;
        config::save(&cfg).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_add_bypass_address(state: tauri::State<AppState>, value: String) -> Result<AppConfig, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        config::add_bypass_address(&mut cfg, value).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_remove_bypass_address(state: tauri::State<AppState>, id: String) -> Result<AppConfig, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        config::remove_bypass_address(&mut cfg, &id).map_err(|e| e.to_string())?;
    }
    reconnect_if_active(&state);
    Ok(state.config.lock().unwrap().clone())
}

#[tauri::command]
fn vpn_set_send_hwid(state: tauri::State<AppState>, enable: bool) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    cfg.tunnel.subscription.send_hwid = enable;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn get_hwid() -> String {
    vpn_manager::compute_hwid()
}

// ---------------------------------------------------------------------------------------
// Подписки
// ---------------------------------------------------------------------------------------

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Применяет результат загрузки к подписке `sub_id`: обновляет метаданные (трафик, срок,
/// интервал, ссылки) и ПЕРЕСОБИРАЕТ список её серверов. Серверы с прежней ссылкой сохраняют
/// свой id — иначе после каждого обновления терялся бы выбранный/подключённый сервер.
fn apply_fetched(
    cfg: &mut AppConfig,
    sub_id: &str,
    f: vpn_manager::FetchedSubscription,
) -> Result<(), String> {
    let existing: Vec<config::VpnServer> = cfg
        .vpn_servers
        .iter()
        .filter(|s| s.sub_id.as_deref() == Some(sub_id))
        .cloned()
        .collect();

    let mut used = std::collections::HashSet::new();
    let mut merged = Vec::with_capacity(f.servers.len());
    for mut server in f.servers {
        if let Some(old) = existing
            .iter()
            .find(|o| o.raw_link == server.raw_link && !used.contains(&o.id))
        {
            server.id = old.id.clone();
        }
        used.insert(server.id.clone());
        server.sub_id = Some(sub_id.to_string());
        merged.push(server);
    }

    cfg.vpn_servers.retain(|s| s.sub_id.as_deref() != Some(sub_id));
    cfg.vpn_servers.extend(merged);

    if let Some(active) = cfg.vpn_active_id.clone() {
        if !cfg.vpn_servers.iter().any(|s| s.id == active) {
            cfg.vpn_active_id = None;
        }
    }

    let sub = cfg
        .subscriptions
        .iter_mut()
        .find(|s| s.id == sub_id)
        .ok_or("подписка не найдена")?;
    if let Some(title) = f.title {
        sub.name = title;
    }
    if let Some(h) = f.interval_hours {
        sub.interval_hours = h;
    }
    sub.upload = f.upload;
    sub.download = f.download;
    sub.total = f.total;
    sub.expire = f.expire;
    sub.support_url = f.support_url;
    sub.web_page_url = f.web_page_url;
    sub.announce = f.announce;
    sub.last_updated = now_unix();
    Ok(())
}

async fn refresh_subscription(st: &AppState, id: &str) -> Result<(), String> {
    let (url, ua, send_hwid) = {
        let cfg = st.config.lock().unwrap();
        let sub = cfg
            .subscriptions
            .iter()
            .find(|s| s.id == id)
            .ok_or("подписка не найдена")?;
        (sub.url.clone(), sub.user_agent.clone(), cfg.tunnel.subscription.send_hwid)
    };
    let fetched = vpn_manager::fetch_subscription(&url, send_hwid, ua.as_deref()).await?;

    let mut cfg = st.config.lock().unwrap();
    apply_fetched(&mut cfg, id, fetched)?;
    config::save(&cfg).map_err(|e| e.to_string())
}

/// Добавляет подписку по URL: скачивает, создаёт запись и сразу наполняет её серверами.
#[tauri::command]
async fn sub_add(
    state: tauri::State<'_, AppState>,
    url: String,
    user_agent: Option<String>,
) -> Result<AppConfig, String> {
    let st = state.inner();
    let url = url.trim().to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("ссылка подписки должна начинаться с http:// или https://".into());
    }
    let (send_hwid, duplicate) = {
        let cfg = st.config.lock().unwrap();
        (
            cfg.tunnel.subscription.send_hwid,
            cfg.subscriptions.iter().any(|s| s.url == url),
        )
    };
    if duplicate {
        return Err("эта подписка уже добавлена".into());
    }

    let ua = user_agent.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    let fetched = vpn_manager::fetch_subscription(&url, send_hwid, ua.as_deref()).await?;

    // Запасное имя — хост из URL, если панель не прислала profile-title.
    let fallback_name = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("подписка")
        .to_string();
    let id = vpn_manager::new_id("sub");

    let mut cfg = st.config.lock().unwrap();
    cfg.subscriptions.push(config::Subscription {
        id: id.clone(),
        name: fallback_name,
        url,
        user_agent: ua,
        interval_hours: 12,
        ..Default::default()
    });
    apply_fetched(&mut cfg, &id, fetched)?;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
async fn sub_refresh(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<AppConfig, String> {
    let st = state.inner();
    refresh_subscription(st, &id).await?;
    Ok(st.config.lock().unwrap().clone())
}

#[tauri::command]
async fn sub_remove(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<AppConfig, String> {
    let st = state.inner();

    // Если подключены через сервер из удаляемой подписки — сначала отключаемся.
    let active_in_sub = {
        let cfg = st.config.lock().unwrap();
        cfg.vpn_active_id
            .as_ref()
            .map(|a| {
                cfg.vpn_servers
                    .iter()
                    .any(|s| &s.id == a && s.sub_id.as_deref() == Some(id.as_str()))
            })
            .unwrap_or(false)
    };
    if active_in_sub && st.vpn.is_running() {
        disconnect_inner(st).await?;
    }

    let mut cfg = st.config.lock().unwrap();
    cfg.vpn_servers.retain(|s| s.sub_id.as_deref() != Some(id.as_str()));
    cfg.subscriptions.retain(|s| s.id != id);
    if let Some(active) = cfg.vpn_active_id.clone() {
        if !cfg.vpn_servers.iter().any(|s| s.id == active) {
            cfg.vpn_active_id = None;
        }
    }
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn sub_set_interval(
    state: tauri::State<AppState>,
    id: String,
    hours: u32,
) -> Result<AppConfig, String> {
    let mut cfg = state.config.lock().unwrap();
    let sub = cfg
        .subscriptions
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or("подписка не найдена")?;
    sub.interval_hours = hours;
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn vpn_get_logs(state: tauri::State<AppState>) -> Vec<String> {
    state.vpn.recent_logs()
}

#[tauri::command]
fn zapret_get_logs(state: tauri::State<AppState>) -> Vec<String> {
    state.zapret.recent_logs()
}

#[tauri::command]
fn tgproxy_get_logs(state: tauri::State<AppState>) -> Vec<String> {
    state.tgproxy.recent_logs()
}

/// Ссылка tg://proxy?... которую tg-ws-proxy-rs печатает в stdout при старте —
/// без неё включённый tgproxy ничем не поможет, это и есть то, что нужно открыть
/// в Telegram (или вставить вручную в Настройки → Прокси).
#[tauri::command]
fn tgproxy_get_link(state: tauri::State<AppState>) -> Option<String> {
    state.tgproxy.proxy_link()
}

#[tauri::command]
fn vpn_get_stats(state: tauri::State<AppState>) -> Result<vpn_manager::StatsSnapshot, String> {
    if !state.vpn.is_running() {
        return Err("VPN не подключён".into());
    }
    // Счётчики трафика берутся из Stats API xray — у sing-box-режимов его нет.
    if matches!(
        state.vpn.mode(),
        tun_mode::VpnMode::SingBox | tun_mode::VpnMode::Adaptive
    ) {
        return Err("статистика недоступна в режимах на sing-box".into());
    }
    vpn_manager::query_stats(&state.resources_dir)
}

/// Пинг одного сервера (TCP-подключение до его адреса). Асинхронный: раньше команда была
/// синхронной, а синхронные команды Tauri 1.x выполняются в потоке окна — пинг недоступного
/// сервера (до таймаута) подвешивал весь интерфейс.
#[tauri::command]
async fn vpn_ping(state: tauri::State<'_, AppState>, id: String) -> Result<u128, String> {
    let server = state
        .config
        .lock()
        .unwrap()
        .vpn_servers
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .ok_or("сервер не найден")?;
    let (host, port) = vpn_manager::server_endpoint(&server)?;
    vpn_manager::ping_host_async(host, port)
        .await
        .ok_or_else(|| "недоступен".to_string())
}

/// Пинг сразу многих серверов (кнопка со спидометром у подписки): до 24 одновременно,
/// результат каждого сервера приходит событием `vpn-ping` {id, ms|null} по мере готовности —
/// интерфейс заполняется на глазах, а не ждёт конца всего списка.
#[tauri::command]
async fn vpn_ping_many(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    ids: Vec<String>,
) -> Result<(), String> {
    let targets: Vec<(String, String, u16)> = {
        let cfg = state.config.lock().unwrap();
        ids.iter()
            .filter_map(|id| cfg.vpn_servers.iter().find(|s| &s.id == id))
            .filter_map(|s| {
                vpn_manager::server_endpoint(s)
                    .ok()
                    .map(|(h, p)| (s.id.clone(), h, p))
            })
            .collect()
    };

    let sem = Arc::new(tokio::sync::Semaphore::new(24));
    let mut handles = Vec::with_capacity(targets.len());
    for (id, host, port) in targets {
        let sem = sem.clone();
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await;
            let ms = vpn_manager::ping_host_async(host, port).await;
            let _ = app.emit_all("vpn-ping", serde_json::json!({ "id": id, "ms": ms }));
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

/// Какие из трёх наборов ресурсов (zapret/tg-ws-proxy/xray) уже установлены — фронтенд
/// использует это, чтобы решить, показывать ли экран первоначальной загрузки.
#[tauri::command]
fn resources_status(state: tauri::State<AppState>) -> (bool, bool, bool) {
    bootstrap::resources_present(&state.resources_dir)
}

fn main() {
    // Приложение живёт в трее и после закрытия окна продолжает работать, поэтому повторный
    // запуск ярлыка не должен поднимать вторую копию (она дралась бы за порты 10808/10809,
    // TUN-адаптер и WinDivert). Вторая копия просит первую показать окно и тут же выходит.
    let listener = match instance::acquire() {
        instance::Guard::Secondary => return,
        instance::Guard::Primary(l) => Some(l),
        instance::Guard::Unavailable => None,
    };

    tauri::Builder::default()
        .setup(move |app| {
            if let Some(l) = listener {
                let h = app.handle();
                instance::serve(l, move || tray::show_main_window(&h));
            }
            tray::spawn_sync_loop(app.handle());

            let resources_dir = proc_util::strip_verbatim(
                app.path_resolver()
                    .resource_dir()
                    .unwrap_or_else(|| PathBuf::from("resources")),
            );

            let mut cfg = config::load();
            // Серверы, сохранённые до появления тегов (формат/транспорт/защита), получают их
            // здесь — по тому же outbound, с которым реально запускается ядро.
            for server in cfg.vpn_servers.iter_mut() {
                if server.format.is_empty() {
                    vpn_manager::fill_meta(server);
                }
            }
            let zapret = Arc::new(ZapretManager::new(resources_dir.clone()));
            let tgproxy = Arc::new(TgProxyManager::new(resources_dir.clone()));
            let vpn = Arc::new(VpnManager::new(resources_dir.clone()));

            // После сбоя или принудительного закрытия прошлого сеанса могли остаться процессы ядер,
            // winws.exe и tg-ws-proxy без хозяина — они держат порты, TUN-адаптер и драйвер WinDivert.
            // Подметаем их ДО запуска чего-либо (второго экземпляра приложения быть не может — см.
            // instance.rs).
            vpn.sweep_orphans();
            zapret.sweep_orphans();
            tgproxy.sweep_orphans();

            // Пустые серверы DC и размер пула заполняем стандартными значениями.
            if cfg.tgproxy_settings.dc_ips.is_empty() {
                cfg.tgproxy_settings.dc_ips = config::TgProxySettings::default().dc_ips;
            }
            if cfg.tgproxy_settings.pool_size == 0 {
                cfg.tgproxy_settings.pool_size = 1;
            }
            let _ = config::save(&cfg);
            // Битый tg-ws-proxy.exe (не программа Windows) удаляем: при старте приложение скачает его заново.
            let tg_exe = resources_dir.join("tgproxy").join("tg-ws-proxy.exe");
            if tg_exe.exists() && !tgproxy_manager::is_pe_file(&tg_exe) {
                let _ = std::fs::remove_file(&tg_exe);
            }
            // Старая форма сохраняла "только WebSocket" (pinned=ws): без запасных способов прокси
            // печатает ссылку, но Telegram через него не подключается. Возвращаем стандартный порядок.
            if cfg.tgproxy_settings.pinned_upstream.trim() == "ws" {
                cfg.tgproxy_settings.pinned_upstream.clear();
                let _ = config::save(&cfg);
            }
            // tg-ws-proxy: постоянный секрет (иначе ссылка tg://proxy менялась бы при каждом запуске)
            // и аргументы командной строки из сохранённых настроек.
            if cfg.tgproxy_settings.secret.trim().is_empty() {
                cfg.tgproxy_settings.secret = tgproxy_manager::random_secret();
                let _ = config::save(&cfg);
            }
            tgproxy.set_args(tgproxy_manager::build_args(&cfg.tgproxy_settings));
            if cfg.tgproxy_enabled {
                let _ = tgproxy.start();
            }
            zapret.set_user_enabled(cfg.zapret_enabled);
            vpn.set_mode(tun_mode::VpnMode::parse(&cfg.vpn_mode));
            vpn.set_plan(tun_mode::load_cached_plan(&resources_dir));

            let state = AppState {
                config: Mutex::new(cfg),
                zapret: zapret.clone(),
                tgproxy,
                vpn,
                resources_dir: resources_dir.clone(),
                vpn_epoch: std::sync::atomic::AtomicU64::new(0),
                vpn_started: Mutex::new(None),
            };
            // Состояние регистрируем ДО запуска любых фоновых задач: они берут его через
            // app_handle.state::<AppState>(), и если задача стартует раньше manage() —
            // приложение падает с паникой "state not managed".
            app.manage(state);

            // Фоновый watcher: пересчитывает PID whitelist-приложений каждые 2с
            // и перезапускает winws.exe с новым --wf-raw при изменении набора PID.
            // Именно этот цикл реализует "запрет работы обхода для всех, кроме
            // выбранных приложений": winws.exe физически не запускается/останавливается
            // в зависимости от того, живы ли whitelisted-процессы, а фильтр жёстко
            // привязан к их PID.
            let app_handle = app.handle();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<AppState>();
                let whitelist_src = state.config.lock().unwrap().whitelist.clone();
                let strategy_src = state.config.lock().unwrap().strategy.clone();
                let resources_dir = state.resources_dir.clone();
                drop(whitelist_src);
                drop(strategy_src);

                let app_handle2 = app_handle.clone();
                let get_whitelist = move || {
                    app_handle2
                        .state::<AppState>()
                        .config
                        .lock()
                        .unwrap()
                        .whitelist
                        .clone()
                };

                let app_handle3 = app_handle.clone();
                let resources_dir2 = resources_dir.clone();
                let last_err = Arc::new(Mutex::new(String::new()));
                let get_strategy_args = move || {
                    let strategy = app_handle3
                        .state::<AppState>()
                        .config
                        .lock()
                        .unwrap()
                        .strategy
                        .clone();
                    let zapret_dir = resources_dir2.join("zapret");
                    let bin_dir = zapret_dir.join("bin");
                    let lists_dir = zapret_dir.join("lists");
                    // Компоненты ещё качаются (первый запуск): ждём молча, без ошибок в журнале.
                    let available = strategies::list_strategies(&zapret_dir);
                    if available.is_empty() {
                        app_handle3.state::<AppState>().zapret.set_args_error(Some(
                            "компоненты zapret ещё не загружены — дождитесь окончания загрузки".to_string(),
                        ));
                        return vec![];
                    }
                    // Выбранной стратегии нет на диске — берём доступную (general.bat, если есть).
                    let strategy = if available.contains(&strategy) {
                        strategy
                    } else if available.iter().any(|s| s == "general.bat") {
                        "general.bat".to_string()
                    } else {
                        available[0].clone()
                    };
                    match strategies::build_args(&strategy, &zapret_dir, &bin_dir, &lists_dir) {
                        Ok(args) => {
                            app_handle3.state::<AppState>().zapret.set_args_error(None);
                            args
                        }
                        Err(e) => {
                            app_handle3
                                .state::<AppState>()
                                .zapret
                                .set_args_error(Some(e.to_string()));
                            let msg = format!("[zapret] не удалось собрать аргументы стратегии {strategy}: {e}");
                            let mut last = last_err.lock().unwrap();
                            if *last != msg {
                                app_handle3.state::<AppState>().zapret.push_external_log(msg.clone());
                                *last = msg;
                            }
                            vec![]
                        }
                    }
                };

                zapret_manager::watch_loop(zapret, get_whitelist, get_strategy_args).await;
            });

            // Фоновая автопроверка обновлений zapret/tg-ws-proxy: раз в 6 часов (и один раз
            // сразу после старта) сверяет tag_name последнего релиза на GitHub с сохранённой
            // версией и, если auto_update включён в конфиге, сама скачивает и подменяет файлы.
            // Если auto_update выключен — просто обновляет last_checked/доступные версии,
            // чтобы UI мог показать "доступно обновление" без автоприменения.
            let app_handle_upd = app.handle();
            tauri::async_runtime::spawn(async move {
                loop {
                    let state = app_handle_upd.state::<AppState>();
                    let (auto_update, zapret_ver, tgproxy_ver, xray_ver, resources_dir) = {
                        let cfg = state.config.lock().unwrap();
                        (
                            cfg.auto_update,
                            cfg.zapret_version.clone(),
                            cfg.tgproxy_version.clone(),
                            cfg.xray_version.clone(),
                            state.resources_dir.clone(),
                        )
                    };

                    if let Ok(check) = updater::check_zapret(zapret_ver.as_deref()).await {
                        if auto_update && check.update_available {
                            state.zapret.pause_for_update();
                            let applied = updater::apply_zapret_update(&check, &resources_dir).await;
                            state.zapret.resume_after_update();
                            if applied.is_ok() {
                                let mut cfg = state.config.lock().unwrap();
                                cfg.zapret_version = Some(check.latest_version.clone());
                                let _ = config::save(&cfg);
                            } else if let Err(e) = applied {
                                eprintln!("[updater] обновление zapret не удалось: {e}");
                            }
                        }
                    }

                    if let Ok(check) = updater::check_tgproxy(tgproxy_ver.as_deref()).await {
                        if auto_update && check.update_available {
                            let was_running = state.tgproxy.is_running();
                            state.tgproxy.stop();
                            let applied = updater::apply_tgproxy_update(&check, &resources_dir).await;
                            if was_running {
                                let _ = state.tgproxy.start();
                            }
                            if applied.is_ok() {
                                let mut cfg = state.config.lock().unwrap();
                                cfg.tgproxy_version = Some(check.latest_version.clone());
                                let _ = config::save(&cfg);
                            } else if let Err(e) = applied {
                                eprintln!("[updater] обновление tg-ws-proxy не удалось: {e}");
                            }
                        }
                    }

                    if let Ok(check) = updater::check_xray(xray_ver.as_deref()).await {
                        if auto_update && check.update_available {
                            let (active_id, tunnel) = {
                                let cfg = state.config.lock().unwrap();
                                (cfg.vpn_active_id.clone(), cfg.tunnel.clone())
                            };
                            state.vpn.stop();
                            let applied = updater::apply_xray_update(&check, &resources_dir).await;
                            if applied.is_ok() {
                                if let Some(id) = active_id {
                                    let server = state
                                        .config
                                        .lock()
                                        .unwrap()
                                        .vpn_servers
                                        .iter()
                                        .find(|s| s.id == id)
                                        .cloned();
                                    if let Some(server) = server {
                                        let _ = state.vpn.connect(&server, &tunnel);
                                    }
                                }
                                let mut cfg = state.config.lock().unwrap();
                                cfg.xray_version = Some(check.latest_version.clone());
                                let _ = config::save(&cfg);
                            } else if let Err(e) = applied {
                                eprintln!("[updater] обновление xray не удалось: {e}");
                            }
                        }
                    }

                    {
                        let mut cfg = state.config.lock().unwrap();
                        cfg.last_checked = Some(chrono::Utc::now().to_rfc3339());
                        let _ = config::save(&cfg);
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(6 * 60 * 60)).await;
                }
            });


            // Первичная загрузка недостающих компонентов (zapret/tg-ws-proxy/xray) с GitHub —
            // чтобы не заставлять пользователя вручную искать релизы и раскладывать файлы.
            // Запускается один раз при старте; уже установленные компоненты не трогает.
            let app_handle_boot = app.handle();
            let resources_dir_boot = resources_dir.clone();
            tauri::async_runtime::spawn(async move {
                let app_handle_for_setter = app_handle_boot.clone();
                bootstrap::run(app_handle_boot, resources_dir_boot, move |field, value| {
                    let state = app_handle_for_setter.state::<AppState>();
                    let mut cfg = state.config.lock().unwrap();
                    match field {
                        "zapret_version" => cfg.zapret_version = Some(value),
                        "tgproxy_version" => cfg.tgproxy_version = Some(value),
                        "xray_version" => cfg.xray_version = Some(value),
                        _ => {}
                    }
                    let _ = config::save(&cfg);
                })
                .await;
            });

            // Автообновление подписок: раз в 5 минут проверяем, у каких вышел их интервал
            // (profile-update-interval от панели или выбранный пользователем), и обновляем.
            // Первая проверка — через 20 секунд после старта, чтобы не мешать запуску.
            let sub_handle = app.handle();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                loop {
                    let st = sub_handle.state::<AppState>();
                    let now = now_unix();
                    let due: Vec<String> = {
                        let cfg = st.config.lock().unwrap();
                        cfg.subscriptions
                            .iter()
                            .filter(|s| {
                                s.interval_hours > 0
                                    && now - s.last_updated >= s.interval_hours as i64 * 3600
                            })
                            .map(|s| s.id.clone())
                            .collect()
                    };
                    let mut changed = false;
                    for id in due {
                        if refresh_subscription(st.inner(), &id).await.is_ok() {
                            changed = true;
                        }
                    }
                    if changed {
                        let _ = sub_handle.emit_all("subscriptions-changed", ());
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                }
            });

            Ok(())
        })
        .system_tray(tray::build())
        .on_system_tray_event(|app, event| tray::on_event(app, event))
        // Закрытие окна (крестик, Alt+F4) не завершает приложение, а прячет его в трей.
        // Полностью выйти можно из меню трея — пункт «Выйти».
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                api.prevent_close();
                let _ = event.window().hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            add_whitelisted_app,
            remove_whitelisted_app,
            set_strategy,
            list_running_apps,
            available_strategies,
            is_zapret_running,
            stop_zapret,
            toggle_zapret,
            lists::zapret_list_files,
            lists::zapret_read_list,
            lists::zapret_write_list,
            lists::zapret_restore_list,
            lists::zapret_set_pinned,
            zapret_remove_services,
            zapret_status,
            component_sources,
            profile_save,
            profile_apply,
            profile_delete,
            profile_presets,
            vpn_started_at,
            tgproxy_get_settings,
            tgproxy_default_settings,
            tgproxy_new_secret,
            tgproxy_preview_args,
            tgproxy_save_settings,
            zapret_test_strategy,
            zapret_test_all_strategies,
            toggle_tgproxy,
            check_status,
            check_for_updates,
            apply_update,
            toggle_auto_update,
            vpn_add_server,
            vpn_remove_server,
            vpn_connect,
            vpn_disconnect,
            vpn_is_connected,
            vpn_toggle_system_proxy,
            vpn_set_fragment,
            vpn_set_mux,
            vpn_set_dns,
            vpn_add_routing_rule,
            vpn_remove_routing_rule,
            vpn_set_per_app,
            vpn_apply_per_app,
            vpn_set_sniffing,
            vpn_add_bypass_address,
            vpn_remove_bypass_address,
            vpn_set_send_hwid,
            get_hwid,
            sub_add,
            sub_refresh,
            sub_remove,
            sub_set_interval,
            vpn_ping_many,
            vpn_get_logs,
            zapret_get_logs,
            tgproxy_get_logs,
            tgproxy_get_link,
            vpn_get_stats,
            vpn_ping,
            vpn_set_mode,
            vpn_get_plan,
            vpn_recalibrate,
            resources_status,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            // При выходе обязательно гасим VPN и убираем системный прокси: иначе TUN-ядро
            // (и маршруты/адаптер) остались бы жить после закрытия окна, а в реестре
            // висел бы прокси на порт, который больше никто не слушает.
            if let tauri::RunEvent::Exit = event {
                if let Some(st) = app_handle.try_state::<AppState>() {
                    shutdown_services(st.inner());
                }
            }
        });
}
