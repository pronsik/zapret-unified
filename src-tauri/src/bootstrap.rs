use serde::Serialize;
use std::path::PathBuf;
use tauri::Manager;

#[derive(Serialize, Clone)]
pub struct BootstrapProgress {
    pub component: String, // "zapret" | "tgproxy" | "xray"
    pub status: String,    // "downloading" | "done" | "error" | "skipped"
    pub message: String,
}

fn emit(app: &tauri::AppHandle, component: &str, status: &str, message: &str) {
    let _ = app.emit_all(
        "bootstrap-progress",
        BootstrapProgress {
            component: component.into(),
            status: status.into(),
            message: message.into(),
        },
    );
}

/// true, если ключевой исполняемый файл раздела уже лежит на месте — считаем, что
/// ресурс уже установлен (руками или предыдущим запуском бутстрапа) и трогать не нужно.
pub fn resources_present(resources_dir: &PathBuf) -> (bool, bool, bool) {
    // zapret готов, только когда есть и бинарник, и хотя бы одна стратегия (.bat).
    // Раньше хватало winws.exe, и при неполной загрузке стратегий приложение не докачивало их.
    let zapret_dir = resources_dir.join("zapret");
    let zapret_ok = zapret_dir.join("bin").join("winws.exe").exists()
        && !crate::strategies::list_strategies(&zapret_dir).is_empty();
    let tgproxy_ok = resources_dir.join("tgproxy").join("tg-ws-proxy.exe").exists();
    let xray_ok = resources_dir.join("xray").join("xray.exe").exists();
    (zapret_ok, tgproxy_ok, xray_ok)
}

/// Скачивает недостающие компоненты (zapret / tg-ws-proxy / xray-core) с GitHub при первом
/// запуске, чтобы пользователю не пришлось вручную искать релизы и раскладывать файлы по
/// папкам — та же боль, из-за которой раньше приходилось объяснять это в README по шагам.
/// Каждый компонент качается независимо — ошибка с одним не блокирует остальные.
pub async fn run(app: tauri::AppHandle, resources_dir: PathBuf, state_setter: impl Fn(&str, String)) {
    let (zapret_ok, tgproxy_ok, xray_ok) = resources_present(&resources_dir);

    if zapret_ok {
        emit(&app, "zapret", "skipped", "уже установлен");
    } else {
        emit(&app, "zapret", "downloading", "скачиваю zapret-discord-youtube…");
        match crate::updater::check_zapret(None).await {
            Ok(check) => match crate::updater::apply_zapret_update(&check, &resources_dir).await {
                Ok(_) => {
                    state_setter("zapret_version", check.latest_version.clone());
                    emit(&app, "zapret", "done", &format!("готово: {}", check.latest_version));
                }
                Err(e) => emit(&app, "zapret", "error", &e.to_string()),
            },
            Err(e) => emit(&app, "zapret", "error", &e.to_string()),
        }
    }

    if tgproxy_ok {
        emit(&app, "tgproxy", "skipped", "уже установлен");
    } else {
        emit(&app, "tgproxy", "downloading", "скачиваю tg-ws-proxy…");
        match crate::updater::check_tgproxy(None).await {
            Ok(check) => match crate::updater::apply_tgproxy_update(&check, &resources_dir).await {
                Ok(_) => {
                    state_setter("tgproxy_version", check.latest_version.clone());
                    emit(&app, "tgproxy", "done", &format!("готово: {}", check.latest_version));
                }
                Err(e) => emit(&app, "tgproxy", "error", &e.to_string()),
            },
            Err(e) => emit(&app, "tgproxy", "error", &e.to_string()),
        }
    }

    if xray_ok {
        emit(&app, "xray", "skipped", "уже установлен");
    } else {
        emit(&app, "xray", "downloading", "скачиваю xray-core…");
        match crate::updater::check_xray(None).await {
            Ok(check) => match crate::updater::apply_xray_update(&check, &resources_dir).await {
                Ok(_) => {
                    state_setter("xray_version", check.latest_version.clone());
                    emit(&app, "xray", "done", &format!("готово: {}", check.latest_version));
                }
                Err(e) => emit(&app, "xray", "error", &e.to_string()),
            },
            Err(e) => emit(&app, "xray", "error", &e.to_string()),
        }
    }

    emit(&app, "all", "done", "бутстрап завершён");
}
