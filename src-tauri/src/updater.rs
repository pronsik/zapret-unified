use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::path::{Path, PathBuf};

pub const ZAPRET_REPO: &str = "Flowseal/zapret-discord-youtube";
// ВАЖНО: это НЕ Flowseal/tg-ws-proxy. Оригинал — полноценное desktop-приложение
// (GUI на customtkinter, иконка в трее, собственный автообновлятор), его релизы —
// готовые .exe-инсталляторы/портативные сборки без .zip, под headless-встраивание
// не годится в принципе. valnesfjord/tg-ws-proxy-rs — независимый headless-порт того
// же протокола на Rust с CLI-флагами, который официально собирает Windows-таргет
// (x86_64-pc-windows-gnu) в release-пайплайне и публикует его отдельным .zip.
pub const TGPROXY_REPO: &str = "valnesfjord/tg-ws-proxy-rs";
pub const XRAY_REPO: &str = "XTLS/Xray-core";
const USER_AGENT: &str = "zapret-unified-updater";

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct UpdateCheck {
    pub component: String,
    pub current_version: Option<String>,
    pub latest_version: String,
    pub update_available: bool,
    pub download_url: Option<String>,
}

async fn fetch_latest_release(repo: &str) -> anyhow::Result<GhRelease> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json::<GhRelease>().await?)
}

/// Выбирает подходящий asset релиза — .zip архив (единственный/первый попавшийся,
/// т.к. в обоих репозиториях релиз обычно содержит один основной архив).
/// Если в релизе несколько .zip (например отдельно x64/x86 сборки), стоит уточнить
/// правило здесь под конкретное имя ассета — в момент написания у Flowseal один архив.
fn pick_zip_asset(release: &GhRelease) -> Option<&GhAsset> {
    release.assets.iter().find(|a| a.name.ends_with(".zip"))
}

/// Как pick_zip_asset, но для релизов с несколькими платформенными архивами в одном
/// релизе (у Xray-core это Xray-windows-64.zip, Xray-windows-32.zip, Xray-linux-64.zip,
/// Xray-macos-*.zip и т.д. одновременно) — берём тот, чьё имя содержит все подстроки
/// из `must_contain` (регистронезависимо).
fn pick_zip_asset_matching<'a>(release: &'a GhRelease, must_contain: &[&str]) -> Option<&'a GhAsset> {
    release.assets.iter().find(|a| {
        let lower = a.name.to_lowercase();
        lower.ends_with(".zip") && must_contain.iter().all(|s| lower.contains(&s.to_lowercase()))
    })
}

pub async fn check_zapret(current: Option<&str>) -> anyhow::Result<UpdateCheck> {
    let release = fetch_latest_release(ZAPRET_REPO).await?;
    let asset = pick_zip_asset(&release);
    Ok(UpdateCheck {
        component: "zapret".into(),
        current_version: current.map(String::from),
        update_available: current != Some(release.tag_name.as_str()),
        download_url: asset.map(|a| a.browser_download_url.clone()),
        latest_version: release.tag_name,
    })
}

/// Релиз valnesfjord/tg-ws-proxy-rs публикует архивы сразу под несколько платформ
/// (Linux musl .tar.gz, macOS, Windows .zip) плюс Android APK в одном релизе — берём
/// именно тот .zip, в имени которого есть "windows", а не первый попавшийся .zip.
pub async fn check_tgproxy(current: Option<&str>) -> anyhow::Result<UpdateCheck> {
    let release = fetch_latest_release(TGPROXY_REPO).await?;
    let asset = pick_zip_asset_matching(&release, &["windows"]);
    Ok(UpdateCheck {
        component: "tgproxy".into(),
        current_version: current.map(String::from),
        update_available: current != Some(release.tag_name.as_str()),
        download_url: asset.map(|a| a.browser_download_url.clone()),
        latest_version: release.tag_name,
    })
}

/// Релизы XTLS/Xray-core содержат сразу несколько платформенных архивов
/// (Xray-windows-64.zip, Xray-windows-32.zip, Xray-linux-64.zip, ...) — берём именно
/// windows-64, т.к. вся остальная сборка (winws.exe/WinDivert) уже завязана на Windows x64.
pub async fn check_xray(current: Option<&str>) -> anyhow::Result<UpdateCheck> {
    let release = fetch_latest_release(XRAY_REPO).await?;
    let asset = pick_zip_asset_matching(&release, &["windows", "64"])
        .filter(|a| !a.name.to_lowercase().contains("arm"));
    Ok(UpdateCheck {
        component: "xray".into(),
        current_version: current.map(String::from),
        update_available: current != Some(release.tag_name.as_str()),
        download_url: asset.map(|a| a.browser_download_url.clone()),
        latest_version: release.tag_name,
    })
}

async fn download_zip(url: &str) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let bytes = client
        .get(url)
        .header("User-Agent", USER_AGENT)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    Ok(bytes.to_vec())
}

/// Распаковывает zip во временную папку и возвращает путь к ней. Архивы GitHub
/// обычно содержат один корневой каталог (repo-name-tag/...), поэтому дальше
/// ищем внутри него нужные подпапки (bin/, lists/) вместо того, чтобы полагаться
/// на фиксированный путь.
fn extract_zip(bytes: &[u8], into: &Path) -> anyhow::Result<()> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    archive.extract(into)?;
    Ok(())
}

/// Ищет первую подпапку с именем `name` где угодно внутри `root` (обход в глубину,
/// т.к. GitHub-архив кладёт всё в один корневой каталог с версией в имени).
fn find_subdir(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().map(|n| n == name).unwrap_or(false) {
                    return Some(path);
                }
                stack.push(path);
            }
        }
    }
    None
}

/// Ищет первый файл где угодно внутри `root`, чьё имя удовлетворяет `pred` (обход в
/// глубину). Нужен для архивов, где неизвестно заранее, лежит бинарник прямо в корне
/// zip или во вложенной папке — в отличие от bin/lists у zapret, тут нет фиксированного
/// имени подпапки, которую можно было бы искать через find_subdir.
fn find_file(root: &Path, pred: impl Fn(&str) -> bool) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if pred(&name.to_lowercase()) {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Файлы lists/, которые обновление не должно затирать: *-user.txt, сам список закреплённых
/// (.pinned) и закреплённые в нём файлы.
fn collect_user_lists(lists_dir: &Path) -> Vec<(String, Vec<u8>)> {
    let pinned: std::collections::HashSet<String> = std::fs::read_to_string(lists_dir.join(".pinned"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(lists_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()).map(String::from) else {
                continue;
            };
            let keep = name.ends_with("-user.txt") || name == ".pinned" || pinned.contains(&name);
            if keep {
                if let Ok(bytes) = std::fs::read(&path) {
                    out.push((name, bytes));
                }
            }
        }
    }
    out
}

fn replace_dir(target: &Path, source: &Path) -> anyhow::Result<()> {
    if target.exists() {
        std::fs::remove_dir_all(target)?;
    }
    std::fs::create_dir_all(target.parent().unwrap_or(target))?;
    copy_dir_recursive(source, target)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let dest_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

/// Скачивает и подменяет bin/ и lists/ внутри resources/zapret. ВАЖНО: вызывающая
/// сторона (main.rs) обязана перед этим вызвать `ZapretManager::pause_for_update()`,
/// а после — `resume_after_update()`, иначе winws.exe может держать файлы открытыми
/// или запуститься поверх недописанного bin/.
pub async fn apply_zapret_update(
    check: &UpdateCheck,
    resources_dir: &Path,
) -> anyhow::Result<()> {
    let url = check
        .download_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("в релизе не найден .zip asset"))?;

    let bytes = download_zip(url).await?;

    let tmp = std::env::temp_dir().join(format!("zapret-update-{}", check.latest_version));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    extract_zip(&bytes, &tmp)?;

    let bin_src = find_subdir(&tmp, "bin")
        .ok_or_else(|| anyhow::anyhow!("в архиве не найдена папка bin/"))?;
    let lists_src = find_subdir(&tmp, "lists")
        .ok_or_else(|| anyhow::anyhow!("в архиве не найдена папка lists/"))?;

    let zapret_dir = resources_dir.join("zapret");
    let lists_dir = zapret_dir.join("lists");

    // replace_dir удаляет папку целиком, а lists/ — это ещё и то, что правит пользователь в
    // редакторе правил. Поэтому до замены запоминаем его файлы и возвращаем их после:
    //   * *-user.txt — собственные правила пользователя (их же создаёт service.bat);
    //   * файлы, которые пользователь "закрепил" (список имён лежит в lists/.pinned).
    // Всё остальное — штатные списки из релиза — обновляется как раньше.
    let preserved = collect_user_lists(&lists_dir);

    replace_dir(&zapret_dir.join("bin"), &bin_src)?;
    replace_dir(&lists_dir, &lists_src)?;

    for (name, bytes) in preserved {
        let _ = std::fs::write(lists_dir.join(name), bytes);
    }

    // bin/ и lists/ — это не всё: сами стратегии обхода (general.bat, general (ALT).bat,
    // ... general (ALT11).bat, discord.bat и т.п.) лежат как *.bat прямо в корне архива,
    // рядом с папкой bin/. Раньше их не копировали вовсе и держали в Rust-коде зашитую
    // руками копию всего двух стратегий — теперь strategies.rs читает эти файлы
    // напрямую, так что их обязательно нужно скопировать вместе с bin/lists.
    let repo_root = bin_src.parent().unwrap_or(&tmp);
    std::fs::create_dir_all(&zapret_dir)?;
    if let Ok(entries) = std::fs::read_dir(repo_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_bat = path
                .extension()
                .map(|e| e.eq_ignore_ascii_case("bat"))
                .unwrap_or(false);
            if is_bat {
                if let Some(name) = path.file_name() {
                    let _ = std::fs::copy(&path, zapret_dir.join(name));
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// tg-ws-proxy-rs паблишит плоский .zip (просто `tg-ws-proxy.exe` в корне, по образцу
/// их же .tar.gz для Linux — `tar -czf name.tar.gz tg-ws-proxy` без подпапок), но на
/// случай, если когда-нибудь появится вложенная структура, ищем .exe по всему архиву,
/// а не полагаемся на фиксированный путь.
pub async fn apply_tgproxy_update(
    check: &UpdateCheck,
    resources_dir: &Path,
) -> anyhow::Result<()> {
    let url = check
        .download_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("в релизе не найден подходящий .zip asset (windows)"))?;

    let bytes = download_zip(url).await?;

    let tmp = std::env::temp_dir().join(format!("tgproxy-update-{}", check.latest_version));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    extract_zip(&bytes, &tmp)?;

    // В архиве может лежать несколько .exe (установщик, деинсталлятор, сама программа).
    let exe_src = find_tgproxy_exe(&tmp)?;

    let tgproxy_dir = resources_dir.join("tgproxy");
    std::fs::create_dir_all(&tgproxy_dir)?;
    std::fs::copy(&exe_src, tgproxy_dir.join("tg-ws-proxy.exe"))?;

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// Архив Xray-core (в отличие от zapret/tg-ws-proxy) плоский — xray.exe и geo*.dat лежат
/// прямо в корне zip, без вложенной папки с версией в имени. Копируем всё содержимое как есть.
pub async fn apply_xray_update(check: &UpdateCheck, resources_dir: &Path) -> anyhow::Result<()> {
    let url = check
        .download_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("в релизе не найден подходящий .zip asset (windows-64)"))?;

    let bytes = download_zip(url).await?;

    let tmp = std::env::temp_dir().join(format!("xray-update-{}", check.latest_version));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    extract_zip(&bytes, &tmp)?;

    let xray_dir = resources_dir.join("xray");
    replace_dir(&xray_dir, &tmp)?;

    Ok(())
}

/// Ищет файл по произвольному условию на ПОЛНЫЙ путь (нужно, когда одинаковые имена
/// лежат в разных подпапках — как wintun.dll в amd64/arm64/x86).
fn find_file_by_path(root: &Path, pred: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if pred(&path) {
                return Some(path);
            }
        }
    }
    None
}

/// Универсальная установка ядра из zip-релиза GitHub в `dest_dir`: берёт первый asset,
/// подходящий под любой из `variants` (каждый вариант — набор подстрок, которые должны
/// быть в имени одновременно) и не содержащий ничего из `must_not`; распаковывает,
/// находит `exe_name` и копирует в `dest_dir` ВСЕ файлы из его папки (рядом с exe часто
/// лежат нужные dll). Возвращает тег установленного релиза.
///
/// Варианты нужны потому, что у разных проектов разные схемы имён
/// (windows-amd64 / x86_64-pc-windows-msvc / win64), и угадывать одну из них вслепую
/// хрупко — перебираем несколько и падаем с понятной ошибкой, если не подошла ни одна.
pub async fn install_release_zip(
    repo: &str,
    variants: &[&[&str]],
    must_not: &[&str],
    exe_name: &str,
    dest_dir: &Path,
) -> anyhow::Result<String> {
    let release = fetch_latest_release(repo).await?;

    let asset = variants
        .iter()
        .find_map(|must| {
            release.assets.iter().find(|a| {
                let lower = a.name.to_lowercase();
                lower.ends_with(".zip")
                    && must.iter().all(|s| lower.contains(&s.to_lowercase()))
                    && !must_not.iter().any(|s| lower.contains(&s.to_lowercase()))
            })
        })
        .ok_or_else(|| {
            anyhow::anyhow!("в релизе {repo} не найден подходящий windows-архив (.zip)")
        })?;

    let bytes = download_zip(&asset.browser_download_url).await?;

    let tmp = std::env::temp_dir().join(format!("core-{}-{}", exe_name, release.tag_name));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    extract_zip(&bytes, &tmp)?;

    let exe_lower = exe_name.to_lowercase();
    let exe_src = find_file(&tmp, |n| n == exe_lower)
        .ok_or_else(|| anyhow::anyhow!("в архиве не найден {exe_name}"))?;
    let payload_dir = exe_src.parent().unwrap_or(&tmp).to_path_buf();

    std::fs::create_dir_all(dest_dir)?;
    for entry in std::fs::read_dir(&payload_dir)?.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name() {
                std::fs::copy(&path, dest_dir.join(name))?;
            }
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(release.tag_name)
}

/// Скачивает официальный wintun.dll (драйвер виртуального адаптера, нужен всем TUN-режимам
/// на Windows) с wintun.net и кладёт amd64-версию в `dest_dir`.
pub async fn install_wintun(dest_dir: &Path) -> anyhow::Result<()> {
    const URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    let bytes = download_zip(URL).await?;
    let tmp = std::env::temp_dir().join("wintun-dl");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    extract_zip(&bytes, &tmp)?;

    let dll = find_file_by_path(&tmp, |p| {
        let s = p.to_string_lossy().to_lowercase();
        s.ends_with("wintun.dll") && s.contains("amd64")
    })
    .ok_or_else(|| anyhow::anyhow!("в архиве wintun не найден amd64/wintun.dll"))?;

    std::fs::create_dir_all(dest_dir)?;
    std::fs::copy(&dll, dest_dir.join("wintun.dll"))?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}


fn exe_name(p: &Path) -> String {
    p.file_name().unwrap_or_default().to_string_lossy().to_lowercase()
}

fn looks_like_installer(name: &str) -> bool {
    name.contains("setup") || name.contains("install") || name.contains("uninst")
}

/// Ищет исполняемый файл tg-ws-proxy в архиве: сначала точное имя, потом похожее; установщики
/// отбрасываются. Файл без сигнатуры "MZ" не принимаем: Windows его потом не запустит.
fn find_tgproxy_exe(root: &Path) -> anyhow::Result<PathBuf> {
    let mut all: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().map(|x| x.eq_ignore_ascii_case("exe")).unwrap_or(false) {
                    all.push(p);
                }
            }
        }
    }
    let pick = all
        .iter()
        .find(|p| exe_name(p) == "tg-ws-proxy.exe")
        .or_else(|| all.iter().find(|p| exe_name(p).contains("tg-ws-proxy") && !looks_like_installer(&exe_name(p))))
        .or_else(|| all.iter().find(|p| !looks_like_installer(&exe_name(p))))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("в архиве не найден исполняемый файл программы"))?;
    if !crate::tgproxy_manager::is_pe_file(&pick) {
        anyhow::bail!("в архиве лежит файл {}, который не является программой Windows", pick.display());
    }
    Ok(pick)
}
