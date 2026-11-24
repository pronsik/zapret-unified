use std::collections::HashMap;
use std::path::Path;

/// Служебные .bat-скрипты репозитория Flowseal/zapret-discord-youtube, которые НЕ
/// являются стратегиями обхода (установка как Windows-сервис, снятие сервиса,
/// обновление hosts и т.п.) — их не показываем как выбираемую стратегию. Это список
/// исключений, а не allowlist: авторы репозитория время от времени добавляют новые
/// general*.bat/discord*.bat варианты, и мы хотим подхватывать их автоматически.
const NON_STRATEGY_PREFIXES: &[&str] = &[
    "service",
    "uninstall",
    "remove",
    "check_updates",
    "update_",
    "test",
];

/// Переменные, которые стратегия получает НЕ из собственных `set`-строк, а из
/// `call service.bat load_game_filter` (оригинальный скрипт зовёт service.bat прямо
/// перед запуском winws.exe). Мы service.bat не выполняем, поэтому подставляем то же
/// значение, что он выставляет при выключенном "Game Filter": безобидный порт 12 —
/// синтаксис `--wf-tcp=80,443,12` остаётся валидным, а расширенный диапазон портов
/// игр не включается. Раньше такие токены отбрасывались целиком, и вместе с ними
/// пропадали --wf-tcp/--wf-udp: winws.exe стартовал без фильтра WinDivert и сразу
/// завершался.
const EXTERNAL_DEFAULTS: &[(&str, &str)] = &[
    ("GameFilterTCP", "12"),
    ("GameFilterUDP", "12"),
    ("GameFilter", "12"),
];

/// Сканирует resources/zapret/*.bat и возвращает список настоящих стратегий обхода —
/// то есть ровно те .bat, что реально лежат на диске после скачивания с GitHub.
pub fn list_strategies(zapret_dir: &Path) -> Vec<String> {
    let mut out = vec![];
    if let Ok(entries) = std::fs::read_dir(zapret_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_bat = path
                .extension()
                .map(|e| e.eq_ignore_ascii_case("bat"))
                .unwrap_or(false);
            if !is_bat {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let lower = name.to_lowercase();
                let is_utility = NON_STRATEGY_PREFIXES.iter().any(|p| lower.starts_with(p));
                if !is_utility {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

fn is_ident(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Собирает `set NAME=значение` из текста батника. Понимает обе формы — `set NAME=value` и
/// каноническую `set "NAME=value"` (с кавычками вокруг ВСЕЙ пары, а не только значения), в
/// том числе после `if ... (` на той же строке. Это не интерпретатор .bat: условия не
/// вычисляются, побеждает последнее найденное значение.
fn parse_set_vars(text: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(pos) = lower.rfind("set ") else { continue };
        // "set" должно быть отдельным словом, а не хвостом вроде "reset "/"offset "
        if pos > 0 && lower.as_bytes()[pos - 1].is_ascii_alphanumeric() {
            continue;
        }
        let after = line[pos + 4..].trim();
        if after.starts_with('/') {
            continue; // set /a, set /p — арифметика и ввод, не присваивание строки
        }
        let after = after.trim_start_matches('"');
        if let Some((name, value)) = after.split_once('=') {
            let name = name.trim();
            if is_ident(name) {
                let value = value.trim().trim_end_matches(')').trim().trim_end_matches('"');
                vars.insert(name.to_string(), value.to_string());
            }
        }
    }
    vars
}

/// Склеивает команду, начатую на строке `start`, со всеми строками-продолжениями (батник
/// переносит строку символом `^` в конце).
fn collect_command(lines: &[&str], start: usize) -> String {
    let mut cmd = String::new();
    let mut idx = start;
    loop {
        let line = lines[idx].trim();
        let continues = line.ends_with('^');
        cmd.push(' ');
        cmd.push_str(line.trim_end_matches('^').trim());
        if !continues || idx + 1 >= lines.len() {
            break;
        }
        idx += 1;
    }
    cmd
}

/// Парсит реальный .bat-файл стратегии и возвращает аргументы для winws.exe (без пути к
/// самому winws.exe), с подстановкой %BIN%/%LISTS%/%~dp0 и прочих переменных на реальные пути.
///
/// Заодно проверяет, что все файлы, на которые ссылается стратегия, существуют: то, что
/// оригинальный service.bat создаёт на лету (*-user.txt, ACTIVE_*.bin), создаётся здесь,
/// остальное — внятная ошибка вместо молчаливого падения winws.exe.
pub fn build_args(
    strategy: &str,
    zapret_dir: &Path,
    bin_dir: &Path,
    lists_dir: &Path,
) -> anyhow::Result<Vec<String>> {
    let bat_path = zapret_dir.join(strategy);
    let text = std::fs::read_to_string(&bat_path)
        .map_err(|e| anyhow::anyhow!("не удалось прочитать {}: {e}", bat_path.display()))?;

    let vars = parse_set_vars(&text);
    let lines: Vec<&str> = text.lines().collect();

    // Ищем именно ЗАПУСК winws.exe: строка с "winws.exe" могла бы встретиться и раньше
    // (проверка запущенного процесса, taskkill), поэтому берём тот блок, где после exe
    // идут настоящие параметры фильтрации.
    let mut after_exe: Option<String> = None;
    for (i, l) in lines.iter().enumerate() {
        if !l.to_ascii_lowercase().contains("winws.exe") {
            continue;
        }
        let cmd = collect_command(&lines, i);
        let Some(pos) = cmd.to_ascii_lowercase().find("winws.exe") else { continue };
        let rest = &cmd[pos + "winws.exe".len()..];
        // После "winws.exe" стоит ЗАКРЫВАЮЩАЯ кавычка пути (`"%BIN%winws.exe" --wf-tcp=...`).
        // Если оставить её, токенайзер примет её за открывающую и склеит весь хвост в один токен.
        let rest = rest.strip_prefix('"').unwrap_or(rest);
        let lower_rest = rest.to_ascii_lowercase();
        if lower_rest.contains("--wf-")
            || lower_rest.contains("--filter-")
            || lower_rest.contains("--dpi-desync")
        {
            after_exe = Some(rest.to_string());
            break;
        }
    }
    let after_exe = after_exe.ok_or_else(|| {
        anyhow::anyhow!("{strategy} не похож на стратегию zapret — не найден запуск winws.exe с параметрами")
    })?;

    let resolved: Vec<String> = tokenize(&after_exe)
        .into_iter()
        .map(|t| expand_vars(&t, &vars, bin_dir, lists_dir, zapret_dir))
        // Токен с по-прежнему нераскрытым %...% (переменная, о которой мы ничего не знаем)
        // отбрасываем — передавать winws.exe буквальный "%Что-то%" хуже, чем пропустить параметр.
        .filter(|t| !t.is_empty() && !t.contains('%'))
        .collect();

    if resolved.is_empty() {
        anyhow::bail!("{strategy}: не удалось разобрать ни одного аргумента winws.exe");
    }

    let mut missing: Vec<String> = Vec::new();
    for t in &resolved {
        let value = t.split_once('=').map(|(_, v)| v).unwrap_or(t.as_str());
        if looks_like_path(value) {
            let p = Path::new(value);
            if !p.exists() && !try_materialize(p) {
                missing.push(value.to_string());
            }
        }
    }
    if !missing.is_empty() {
        anyhow::bail!(
            "{strategy}: не найдены файлы, на которые он ссылается: {}",
            missing.join(", ")
        );
    }

    Ok(resolved)
}

/// Создаёт стандартные пользовательские списки, если их нет (так делает service.bat). Нужны,
/// чтобы редактор правил всегда показывал "свои" файлы, а winws.exe не падал на отсутствующем.
pub fn ensure_user_lists(lists_dir: &Path) {
    let _ = std::fs::create_dir_all(lists_dir);
    for (name, placeholder) in [
        ("list-general-user.txt", "domain.example.abc\n"),
        ("list-exclude-user.txt", "domain.example.abc\n"),
        ("ipset-exclude-user.txt", "203.0.113.113/32\n"),
    ] {
        let p = lists_dir.join(name);
        if !p.exists() {
            let _ = std::fs::write(p, placeholder);
        }
    }
}

fn looks_like_path(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() > 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// Создаёт то, что оригинальный service.bat создаёт на лету перед запуском стратегии:
///  * пользовательские списки (*-user.txt) и любые пропавшие .txt-списки — с безобидной
///    строкой-заглушкой (пустой файл winws.exe не принимает так же охотно);
///  * ACTIVE_*.bin — "активный" фейк, который service.bat копирует из bin/ по выбору
///    пользователя; здесь берём первый подходящий из стандартных.
fn try_materialize(p: &Path) -> bool {
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let lower = name.to_ascii_lowercase();

    if lower.ends_with(".txt") {
        let placeholder = if lower.contains("ipset") {
            "203.0.113.113/32\n"
        } else {
            "domain.example.abc\n"
        };
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        return std::fs::write(p, placeholder).is_ok();
    }

    if lower.starts_with("active_") && lower.ends_with(".bin") {
        if let Some(dir) = p.parent() {
            for fallback in ["stun.bin", "quic_initial_www_google_com.bin"] {
                let src = dir.join(fallback);
                if src.exists() && std::fs::copy(&src, p).is_ok() {
                    return true;
                }
            }
        }
    }
    false
}

fn tokenize(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn expand_vars(
    token: &str,
    vars: &HashMap<String, String>,
    bin_dir: &Path,
    lists_dir: &Path,
    zapret_dir: &Path,
) -> String {
    let mut s = token.to_string();

    // %BIN% / %LISTS% встречаются во всех известных версиях репозитория под этими
    // именами. Подставляем НАШ реальный путь, а не то, что скрипт сам вычислил бы
    // через %~dp0, — мы не запускаем .bat интерпретатором, только читаем его текст.
    s = s.replace("%BIN%", &format!("{}\\", bin_dir.display()));
    s = s.replace("%LISTS%", &format!("{}\\", lists_dir.display()));
    s = s.replace("%~dp0", &format!("{}\\", zapret_dir.display()));

    // Прочие `set`-переменные из самого файла.
    for (name, value) in vars {
        let pat = format!("%{name}%");
        if s.contains(&pat) {
            s = s.replace(&pat, value);
        }
    }

    // Переменные, которые оригинальный .bat получает извне (из service.bat).
    for (name, value) in EXTERNAL_DEFAULTS {
        let pat = format!("%{name}%");
        if s.contains(&pat) {
            s = s.replace(&pat, value);
        }
    }

    s.trim().to_string()
}
