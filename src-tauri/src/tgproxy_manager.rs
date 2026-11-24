use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const MAX_LOG_LINES: usize = 400;

pub struct TgProxyManager {
    child: Mutex<Option<Child>>,
    /// Аргументы запуска, собранные из настроек (`build_args`). Хранятся в менеджере, чтобы все
    /// места, вызывающие `start()` (включение, автообновление, старт приложения), запускали
    /// прокси с одними и теми же настройками.
    args: Mutex<Vec<String>>,
    /// Сериализует start/stop — как и у VPN: пересёкшиеся запуски иначе теряли дескриптор.
    op: Mutex<()>,
    resources_dir: PathBuf,
    logs: std::sync::Arc<Mutex<std::collections::VecDeque<String>>>,
}

impl TgProxyManager {
    pub fn new(resources_dir: PathBuf) -> Self {
        Self {
            child: Mutex::new(None),
            args: Mutex::new(Vec::new()),
            op: Mutex::new(()),
            resources_dir,
            logs: std::sync::Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(MAX_LOG_LINES))),
        }
    }

    fn exe_path(&self) -> PathBuf {
        self.resources_dir.join("tgproxy").join("tg-ws-proxy.exe")
    }

    pub fn recent_logs(&self) -> Vec<String> {
        self.logs.lock().unwrap().iter().cloned().collect()
    }

    /// tg-ws-proxy-rs печатает в stdout готовую ссылку вида "tg://proxy?server=...&secret=..."
    /// при старте — без неё включённый tgproxy бесполезен, т.к. это и есть то, что нужно
    /// вставить в Telegram. Ищем её в уже накопленных логах.
    pub fn proxy_link(&self) -> Option<String> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|line| {
                for marker in ["tg://proxy", "https://t.me/proxy", "http://t.me/proxy"] {
                    if let Some(idx) = line.find(marker) {
                        // обрезаем по пробелу, кавычке и ANSI-escape (\x1b), если программа красит вывод
                        let link = line[idx..]
                            .split(|c: char| c.is_whitespace() || c == '\u{1b}' || c == '"' || c == '\'' || c == '>' || c == ')')
                            .next()?;
                        return Some(link.to_string());
                    }
                }
                None
            })
    }

    fn push_log(logs: &std::sync::Arc<Mutex<std::collections::VecDeque<String>>>, line: String) {
        let mut l = logs.lock().unwrap();
        if l.len() >= MAX_LOG_LINES {
            l.pop_front();
        }
        l.push_back(line);
    }

    pub fn set_args(&self, args: Vec<String>) {
        *self.args.lock().unwrap() = args;
    }

    pub fn start(&self) -> anyhow::Result<()> {
        let _op = self.op.lock().unwrap();
        self.stop_locked();
        self.logs.lock().unwrap().clear();

        let args = self.args.lock().unwrap().clone();
        let exe = self.exe_path();
        if !exe.exists() {
            anyhow::bail!("tg-ws-proxy.exe не найден. Нажмите «обновить» на странице Telegram-прокси.");
        }
        if !is_pe_file(&exe) {
            let _ = std::fs::remove_file(&exe);
            anyhow::bail!("файл tg-ws-proxy.exe повреждён или скачан не тот (не программа Windows). Он удалён — нажмите «обновить», чтобы скачать заново.");
        }
        let mut cmd = Command::new(self.exe_path());
        cmd.args(&args);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let mut child = cmd.spawn()?;

        use std::io::{BufRead, BufReader};
        if let Some(stdout) = child.stdout.take() {
            let logs = self.logs.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().flatten() {
                    Self::push_log(&logs, line);
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let logs = self.logs.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().flatten() {
                    Self::push_log(&logs, format!("[stderr] {line}"));
                }
            });
        }

        *self.child.lock().unwrap() = Some(child);
        Ok(())
    }

    pub fn stop(&self) {
        let _op = self.op.lock().unwrap();
        self.stop_locked();
    }

    fn stop_locked(&self) {
        let child = self.child.lock().unwrap().take();
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.sweep_orphans();
    }

    /// Добивает tg-ws-proxy.exe из нашей папки, потерявшие дескриптор (прошлый сеанс, сбой).
    pub fn sweep_orphans(&self) -> usize {
        crate::process_monitor::sweep_many(
            &[("tg-ws-proxy.exe", self.resources_dir.join("tgproxy"))],
            None,
        )
    }

    pub fn is_running(&self) -> bool {
        let mut guard = self.child.lock().unwrap();
        match guard.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }
}

/// Разбор строки дополнительных флагов с учётом двойных кавычек.
pub fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut has = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                has = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

/// Случайный секрет MTProto: 16 байт = 32 hex-символа. Источник энтропии — `RandomState`
/// (ключи берутся у ОС), смешанный через SHA-256 с временем и PID. Секрет защищает локальный
/// прокси от чужих подключений, а не шифрует трафик Telegram — для этого достаточно.
pub fn random_secret() -> String {
    use sha2::{Digest, Sha256};
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    for i in 0..4u64 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(nanos as u64 ^ i);
        h.update(hasher.finish().to_le_bytes());
    }
    h.finalize()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

const UPSTREAM_TIERS: &[&str] = &["ws", "cfworker", "cfproxy", "mtproto", "tcp"];

/// Проверяет и приводит настройки к каноничному виду. Возвращает понятную ошибку, а не
/// передаёт прокси заведомо неверный флаг.
pub fn normalize_settings(s: &mut crate::config::TgProxySettings) -> Result<(), String> {
    if s.port == 0 {
        return Err("порт должен быть от 1 до 65535".into());
    }
    s.pool_size = s.pool_size.min(256);

    s.secret = s.secret.trim().to_ascii_lowercase();
    if !s.secret.is_empty() && !(s.secret.len() == 32 && s.secret.chars().all(|c| c.is_ascii_hexdigit())) {
        return Err("секрет должен состоять ровно из 32 шестнадцатеричных символов (0-9, a-f)".into());
    }

    let single_line = |name: &str, v: &mut String| -> Result<(), String> {
        *v = v.trim().to_string();
        if v.chars().any(|c| c.is_control()) {
            return Err(format!("поле «{name}» содержит недопустимые символы"));
        }
        Ok(())
    };
    single_line("cf-domain", &mut s.cf_domain)?;
    single_line("cf-worker-domain", &mut s.cf_worker_domain)?;
    single_line("fronting-domain", &mut s.fronting_domain)?;
    single_line("outbound-proxy", &mut s.outbound_proxy)?;
    single_line("pinned-upstream", &mut s.pinned_upstream)?;

    if !s.outbound_proxy.is_empty() {
        let ok = ["http://", "socks5://", "socks5h://"].iter().any(|p| s.outbound_proxy.starts_with(p));
        if !ok {
            return Err("outbound-proxy: допустимы адреса http://, socks5:// или socks5h://".into());
        }
    }

    if !s.pinned_upstream.is_empty() {
        let tiers: Vec<String> = s
            .pinned_upstream
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        if let Some(bad) = tiers.iter().find(|t| !UPSTREAM_TIERS.contains(&t.as_str())) {
            return Err(format!(
                "pinned-upstream: неизвестный способ «{bad}» (допустимы: {})",
                UPSTREAM_TIERS.join(", ")
            ));
        }
        s.pinned_upstream = tiers.join(",");
    }

    s.dc_ips = s.dc_ips.iter().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    for l in &s.dc_ips {
        let ok = l
            .split_once(':')
            .map(|(dc, ip)| dc.parse::<u32>().is_ok() && !ip.is_empty() && !ip.chars().any(|c| c.is_whitespace()))
            .unwrap_or(false);
        if !ok {
            return Err(format!("dc-ip «{l}»: ожидается формат DC:IP, например 2:149.154.167.220"));
        }
    }

    s.mtproto_proxies = s.mtproto_proxies.iter().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    for l in &s.mtproto_proxies {
        if l.matches(':').count() < 2 || l.chars().any(|c| c.is_whitespace()) {
            return Err(format!("mtproto-proxy «{l}»: ожидается формат хост:порт:секрет"));
        }
    }

    s.extra_args = s.extra_args.trim().to_string();
    if s.extra_args.matches('"').count() % 2 != 0 {
        return Err("в дополнительных флагах не закрыта кавычка".into());
    }
    Ok(())
}

/// Аргументы командной строки tg-ws-proxy из настроек.
pub fn build_args(s: &crate::config::TgProxySettings) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    let mut push = |k: &str, v: Option<&str>| {
        a.push(k.to_string());
        if let Some(v) = v {
            a.push(v.to_string());
        }
    };

    push("--host", Some(if s.lan_access { "0.0.0.0" } else { "127.0.0.1" }));
    push("--port", Some(&s.port.to_string()));
    if !s.lan_access {
        // Ссылка tg://proxy должна указывать на адрес, по которому Telegram реально достучится.
        push("--link-ip", Some("127.0.0.1"));
    }
    if !s.secret.is_empty() {
        push("--secret", Some(&s.secret));
    }
    if s.pool_size > 0 {
        push("--pool-size", Some(&s.pool_size.to_string()));
    }
    if s.default_domains {
        push("--default-domains", None);
    }
    if !s.cf_domain.is_empty() {
        push("--cf-domain", Some(&s.cf_domain));
    }
    if !s.cf_worker_domain.is_empty() {
        push("--cf-worker-domain", Some(&s.cf_worker_domain));
    }
    if s.cf_balance {
        push("--cf-balance", None);
    }
    if s.cf_disable_tls {
        push("--cf-disable-tls", None);
    }
    // Способы, которые не настроены (Cloudflare без домена, MTProto без серверов), tg-ws-proxy
    // не принимает: он падает с "pins the cfproxy tier but nothing configures it". Поэтому в
    // запуск передаём только настроенные. Сам список в настройках при этом не меняется.
    let usable: Vec<&str> = s
        .pinned_upstream
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter(|t| match *t {
            "cfworker" => !s.cf_worker_domain.is_empty(),
            "cfproxy" => !s.cf_domain.is_empty(),
            "mtproto" => !s.mtproto_proxies.is_empty(),
            _ => true,
        })
        .collect();
    if !usable.is_empty() {
        let joined = usable.join(",");
        push("--pinned-upstream", Some(&joined));
    }
    if !s.fronting_domain.is_empty() {
        push("--fronting-domain", Some(&s.fronting_domain));
    }
    for d in &s.dc_ips {
        push("--dc-ip", Some(d));
    }
    for m in &s.mtproto_proxies {
        push("--mtproto-proxy", Some(m));
    }
    if !s.outbound_proxy.is_empty() {
        push("--outbound-proxy", Some(&s.outbound_proxy));
    }
    if s.verbose {
        push("-v", None);
    }
    a.extend(split_args(&s.extra_args));
    a
}


/// Настоящая программа Windows начинается с сигнатуры "MZ". Файл без неё (HTML-страница, архив,
/// программа для другой системы) Windows не запускает: ошибка 193 "not a valid win32 application".
pub fn is_pe_file(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 2];
    f.read_exact(&mut head).is_ok() && &head == b"MZ"
}
