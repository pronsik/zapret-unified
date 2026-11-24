use std::collections::HashSet;
use sysinfo::System;

/// Возвращает набор PID процессов, чьё имя .exe входит в whitelist.
/// Один и тот же браузер может иметь несколько процессов (вкладки/GPU/утилиты) —
/// это ожидаемо, обход DPI должен применяться ко всем сетевым потокам приложения.
pub fn resolve_pids(whitelist: &[String]) -> HashSet<u32> {
    let mut sys = System::new();
    sys.refresh_processes();

    let wanted: HashSet<String> = whitelist.iter().map(|s| s.to_lowercase()).collect();

    sys.processes()
        .values()
        .filter(|p| wanted.contains(&p.name().to_lowercase()))
        .map(|p| p.pid().as_u32())
        .collect()
}

/// Список всех запущенных .exe с уникальными именами — используется в UI
/// диалога "добавить приложение", чтобы предложить пользователю то, что реально
/// сейчас работает, а не просить вручную вводить имя.
pub fn list_running_exe_names() -> Vec<String> {
    let mut sys = System::new();
    sys.refresh_processes();

    let mut names: Vec<String> = sys
        .processes()
        .values()
        .map(|p| p.name().to_string())
        .filter(|n| n.to_lowercase().ends_with(".exe"))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Путь к исполняемому файлу первого найденного процесса с таким именем — нужен,
/// чтобы после kill_by_name() перезапустить то же самое приложение с нужными флагами.
pub fn find_exe_path(exe_name: &str) -> Option<std::path::PathBuf> {
    let mut sys = System::new();
    sys.refresh_processes();

    sys.processes()
        .values()
        .find(|p| p.name().eq_ignore_ascii_case(exe_name))
        .and_then(|p| p.exe().map(|e| e.to_path_buf()))
}

/// Завершает все процессы с данным именем .exe (используется перед relaunch с новыми
/// флагами прокси — Chromium не подхватывает --proxy-server на уже запущенном процессе).
pub fn kill_by_name(exe_name: &str) {
    let mut sys = System::new();
    sys.refresh_processes();

    for p in sys.processes().values().filter(|p| p.name().eq_ignore_ascii_case(exe_name)) {
        p.kill();
    }
}

/// Путь для сравнения: нижний регистр, только обратные слэши, без префикса `\\?\`.
fn norm_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().to_lowercase().replace('/', "\\");
    match s.strip_prefix(r"\\?\") {
        Some(rest) => rest.to_string(),
        None => s,
    }
}

/// PID процессов с именем `name`; если задан `dir` — только тех, чей .exe лежит внутри него.
fn collect_pids(sys: &System, name: &str, dir: Option<&std::path::Path>) -> Vec<u32> {
    let base = dir.map(|d| {
        let mut b = norm_path(d);
        if !b.ends_with('\\') {
            b.push('\\');
        }
        b
    });
    sys.processes()
        .values()
        .filter(|p| p.name().eq_ignore_ascii_case(name))
        .filter(|p| match &base {
            None => true,
            Some(b) => p
                .exe()
                .map(|e| norm_path(e).starts_with(b.as_str()))
                .unwrap_or(false),
        })
        .map(|p| p.pid().as_u32())
        .collect()
}

/// PID всех процессов с таким именем во всей системе.
pub fn find_pids_by_name(name: &str) -> Vec<u32> {
    let mut sys = System::new();
    sys.refresh_processes();
    collect_pids(&sys, name, None)
}

/// Добивает "осиротевшие" процессы: запущенные из указанных папок, но уже не принадлежащие
/// никакому `Child` (прошлый сеанс, сбой, затёртый дескриптор). Вызывается ПОСЛЕ остановки
/// собственных процессов, поэтому всё найденное — заведомо лишнее. Возвращает, сколько
/// процессов было завершено.
pub fn sweep_many(
    items: &[(&str, std::path::PathBuf)],
    graceful: Option<std::time::Duration>,
) -> usize {
    let mut sys = System::new();
    sys.refresh_processes();
    let mut n = 0;
    for (name, dir) in items {
        for pid in collect_pids(&sys, name, Some(dir.as_path())) {
            crate::proc_util::stop_pid(pid, graceful);
            n += 1;
        }
    }
    n
}
