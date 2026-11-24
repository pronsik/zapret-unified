//! Редактор правил zapret: файлы resources/zapret/lists/*.txt (списки доменов и IP-подсетей,
//! по которым winws.exe решает, какой трафик обрабатывать).

use crate::AppState;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Файлы больше этого размера в текстовом редакторе приложения открывать бессмысленно.
const MAX_EDITABLE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Serialize)]
pub struct ListFile {
    pub name: String,
    pub size: u64,
    /// Unix-секунды последнего изменения.
    pub modified: i64,
    /// Собственный файл пользователя (*-user.txt) — обновления zapret его не трогают.
    pub user: bool,
    /// Закреплён: обновление zapret не затирает правки в этом файле.
    pub pinned: bool,
    /// Есть сохранённая копия оригинала — можно вернуть исходное содержимое.
    pub has_original: bool,
}

fn lists_dir(st: &AppState) -> PathBuf {
    st.resources_dir.join("zapret").join("lists")
}

/// Имя файла из интерфейса — только простое имя .txt в папке lists: никаких путей, "..", скрытых файлов.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name.to_ascii_lowercase().ends_with(".txt")
        && !name.starts_with('.')
        && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn is_user(name: &str) -> bool {
    name.ends_with("-user.txt")
}

fn read_pinned(dir: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(dir.join(".pinned"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn write_pinned(dir: &Path, set: &BTreeSet<String>) -> Result<(), String> {
    let text: String = set.iter().map(|n| format!("{n}\n")).collect();
    std::fs::write(dir.join(".pinned"), text).map_err(|e| e.to_string())
}

fn file_info(dir: &Path, name: &str, pinned: &BTreeSet<String>) -> Option<ListFile> {
    let meta = std::fs::metadata(dir.join(name)).ok()?;
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Some(ListFile {
        name: name.to_string(),
        size: meta.len(),
        modified,
        user: is_user(name),
        pinned: pinned.contains(name),
        has_original: dir.join(".orig").join(name).exists(),
    })
}

fn checked(name: &str) -> Result<(), String> {
    if valid_name(name) {
        Ok(())
    } else {
        Err("недопустимое имя файла".to_string())
    }
}

/// Список файлов правил: собственные (*-user.txt) сверху, затем остальные по имени.
#[tauri::command]
pub fn zapret_list_files(state: tauri::State<AppState>) -> Result<Vec<ListFile>, String> {
    let dir = lists_dir(state.inner());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    crate::strategies::ensure_user_lists(&dir);

    let pinned = read_pinned(&dir);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(String::from) else {
            continue;
        };
        if !valid_name(&name) {
            continue;
        }
        if let Some(info) = file_info(&dir, &name, &pinned) {
            out.push(info);
        }
    }
    out.sort_by(|a, b| b.user.cmp(&a.user).then(a.name.cmp(&b.name)));
    Ok(out)
}

#[tauri::command]
pub fn zapret_read_list(state: tauri::State<AppState>, name: String) -> Result<String, String> {
    checked(&name)?;
    let path = lists_dir(state.inner()).join(&name);
    let meta = std::fs::metadata(&path).map_err(|_| "файл не найден".to_string())?;
    if meta.len() > MAX_EDITABLE_BYTES {
        return Err(format!(
            "файл слишком большой ({:.1} МБ) для встроенного редактора",
            meta.len() as f64 / 1024.0 / 1024.0
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    Ok(text.trim_start_matches('\u{feff}').replace("\r\n", "\n"))
}

/// Сохраняет файл. Запись атомарная (временный файл + переименование): winws.exe может читать
/// список в этот самый момент, и наполовину записанный файл ему показывать нельзя. Перед первой
/// правкой штатного (не *-user) файла оригинал откладывается в lists/.orig — для кнопки "вернуть
/// исходный". `restart` — перезапустить winws.exe: списки он читает только при старте.
#[tauri::command]
pub fn zapret_write_list(
    state: tauri::State<AppState>,
    name: String,
    content: String,
    restart: bool,
) -> Result<ListFile, String> {
    checked(&name)?;
    if content.len() as u64 > MAX_EDITABLE_BYTES {
        return Err("содержимое слишком большое".to_string());
    }
    let st = state.inner();
    let dir = lists_dir(st);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(&name);

    if !is_user(&name) && path.exists() {
        let orig_dir = dir.join(".orig");
        let orig = orig_dir.join(&name);
        if !orig.exists() {
            let _ = std::fs::create_dir_all(&orig_dir);
            let _ = std::fs::copy(&path, &orig);
        }
    }

    let mut text = content.replace("\r\n", "\n");
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;

    if restart {
        st.zapret.request_restart();
    }
    file_info(&dir, &name, &read_pinned(&dir)).ok_or_else(|| "файл не найден после записи".to_string())
}

/// Возвращает исходное содержимое штатного файла (копию, снятую перед первой правкой).
#[tauri::command]
pub fn zapret_restore_list(state: tauri::State<AppState>, name: String) -> Result<String, String> {
    checked(&name)?;
    let st = state.inner();
    let dir = lists_dir(st);
    let orig = dir.join(".orig").join(&name);
    if !orig.exists() {
        return Err("исходной копии нет: файл ещё не правился из приложения".to_string());
    }
    std::fs::copy(&orig, dir.join(&name)).map_err(|e| e.to_string())?;
    st.zapret.request_restart();
    let bytes = std::fs::read(dir.join(&name)).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&bytes).replace("\r\n", "\n"))
}

#[tauri::command]
pub fn zapret_set_pinned(
    state: tauri::State<AppState>,
    name: String,
    pinned: bool,
) -> Result<(), String> {
    checked(&name)?;
    let dir = lists_dir(state.inner());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut set = read_pinned(&dir);
    if pinned {
        set.insert(name);
    } else {
        set.remove(&name);
    }
    write_pinned(&dir, &set)
}
