use crate::config::VpnServer;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// xray.exe — консольная программа; без этого флага Windows всё равно рисует ей окно
/// консоли, даже когда stdout/stderr уже уведены в пайп (и дальше — в self.logs/лог-панель
/// на странице VPN). Получается пустое висящее окно поверх реального вывода.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
/// Ядра VPN обрабатывают весь пакетный трафик в пользовательском режиме. Под нагрузкой
/// (speedtest, закачка) они конкурируют за процессор с браузером и остальными программами —
/// слегка повышенный приоритет не даёт им "затыкаться", что видно как скачок пинга.
#[cfg(windows)]
const ABOVE_NORMAL_PRIORITY_CLASS: u32 = 0x0000_8000;

pub const SOCKS_PORT: u16 = 10808;
pub const HTTP_PORT: u16 = 10809;
/// Локальный порт для Stats API xray-core (dokodemo-door inbound, см. build_xray_config).
pub const API_PORT: u16 = 10085;

/// -------- Парсинг ссылок --------
/// Поддерживаются форматы, которыми делятся подписки/провайдеры для vless/vmess/trojan/ss.
/// Не претендует на 100% покрытие всех редких комбинаций транспортов (grpc, kcp и т.п.) —
/// поддержаны самые ходовые: tcp/ws (+ tls) и vless+reality.

pub fn parse_link(link: &str) -> Result<VpnServer, String> {
    let mut server = parse_link_raw(link)?;
    fill_meta(&mut server);
    Ok(server)
}

fn parse_link_raw(link: &str) -> Result<VpnServer, String> {
    let link = link.trim();
    if let Some(rest) = link.strip_prefix("vless://") {
        parse_vless(rest)
    } else if let Some(rest) = link.strip_prefix("vmess://") {
        parse_vmess(rest)
    } else if let Some(rest) = link.strip_prefix("trojan://") {
        parse_generic_userinfo(rest, "trojan")
    } else if let Some(rest) = link.strip_prefix("ss://") {
        parse_ss(rest)
    } else {
        Err("неизвестная схема ссылки (ожидается vless/vmess/trojan/ss)".into())
    }
}

fn split_fragment(s: &str) -> (&str, Option<String>) {
    match s.split_once('#') {
        Some((body, name)) => (
            body,
            urlencoding::decode(name).ok().map(|c| c.into_owned()),
        ),
        None => (s, None),
    }
}

/// vless://uuid@host:port?params#name  и trojan://password@host:port?params#name
/// имеют идентичную структуру userinfo@host:port, поэтому общий парсер.
fn parse_generic_userinfo(rest: &str, protocol: &str) -> Result<VpnServer, String> {
    let (body, name) = split_fragment(rest);
    let full_link = format!("{protocol}://{rest}");

    let at_pos = body.find('@').ok_or("не найден '@' (userinfo@host:port)")?;
    let host_port_and_query = &body[at_pos + 1..];

    let host_port = host_port_and_query.split('?').next().unwrap_or("");
    let host = host_port
        .split(':')
        .next()
        .ok_or("не удалось определить хост")?;

    Ok(VpnServer {
        id: uuid_like_id(),
        name: name.unwrap_or_else(|| format!("{protocol}-{host}")),
        protocol: protocol.to_string(),
        raw_link: full_link,
        ..Default::default()
    })
}

fn parse_vless(rest: &str) -> Result<VpnServer, String> {
    parse_generic_userinfo(rest, "vless")
}

fn parse_ss(rest: &str) -> Result<VpnServer, String> {
    let (body, name) = split_fragment(rest);
    let full_link = format!("ss://{rest}");

    // Новый формат: base64(method:password)@host:port
    // Старый формат: base64(method:password@host:port) целиком.
    let host = if let Some(at_pos) = body.find('@') {
        let host_port = body[at_pos + 1..].split('?').next().unwrap_or("");
        host_port.split(':').next().unwrap_or("unknown").to_string()
    } else {
        match STANDARD.decode(body) {
            Ok(decoded) => {
                let s = String::from_utf8_lossy(&decoded);
                let after_at = s.split('@').nth(1).unwrap_or("unknown");
                after_at.split(':').next().unwrap_or("unknown").to_string()
            }
            Err(_) => "unknown".to_string(),
        }
    };

    Ok(VpnServer {
        id: uuid_like_id(),
        name: name.unwrap_or_else(|| format!("ss-{host}")),
        protocol: "shadowsocks".to_string(),
        raw_link: full_link,
        ..Default::default()
    })
}

#[derive(Deserialize)]
struct VmessJson {
    ps: Option<String>,
    add: String,
}

fn parse_vmess(rest: &str) -> Result<VpnServer, String> {
    let decoded = STANDARD
        .decode(rest.trim())
        .map_err(|e| format!("не удалось декодировать base64 vmess: {e}"))?;
    let parsed: VmessJson = serde_json::from_slice(&decoded)
        .map_err(|e| format!("некорректный JSON внутри vmess://: {e}"))?;

    Ok(VpnServer {
        id: uuid_like_id(),
        name: parsed
            .ps
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("vmess-{}", parsed.add)),
        protocol: "vmess".to_string(),
        raw_link: format!("vmess://{rest}"),
        ..Default::default()
    })
}

/// Уникальный id. Раньше был только наносекундный отсчёт времени: при пакетном добавлении
/// (подписка на десятки серверов) два вызова подряд на Windows могут получить одно и то же
/// время и, значит, одинаковый id.
pub(crate) fn new_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{nanos:x}-{n:x}")
}

fn uuid_like_id() -> String {
    new_id("srv")
}

/// -------- Сборка конфига xray-core --------
/// Мы не реализуем полный конвертер каждого поля протокола вручную: xray-core сам умеет
/// принимать share-ссылки через свой конфиг с полем "outbounds" — но так как единого
/// стандарта разбора share-ссылок в самом xray-core (в отличие от v2rayN/GUI-клиентов) нет,
/// собираем outbound JSON из распарсенных полей. Ниже — минимальный, но рабочий набор
/// для tcp/tls и vless+reality, которого достаточно для большинства провайдерских ссылок.
pub fn build_xray_config(server: &VpnServer, tunnel: &crate::config::TunnelSettings) -> Result<Value, String> {
    let mut proxy_outbound = build_outbound(server)?;

    if tunnel.mux.enabled {
        proxy_outbound["mux"] = json!({
            "enabled": true,
            "concurrency": tunnel.mux.concurrency
        });
    }

    let mut outbounds = vec![];

    if tunnel.fragment.enabled {
        // Официальная схема xray-core для фрагментации: outbound "proxy" ссылается через
        // sockopt.dialerProxy на отдельный outbound "fragment" (freedom с полем fragment),
        // который реально режет исходящие пакеты перед тем, как они попадут в proxy-тоннель.
        let stream = proxy_outbound
            .get_mut("streamSettings")
            .map(|s| s.clone())
            .unwrap_or_else(|| json!({}));
        let mut stream = stream;
        stream["sockopt"] = json!({ "dialerProxy": "fragment" });
        proxy_outbound["streamSettings"] = stream;

        outbounds.push(proxy_outbound);
        outbounds.push(json!({
            "tag": "fragment",
            "protocol": "freedom",
            "settings": {
                "fragment": {
                    "packets": tunnel.fragment.packets,
                    "length": tunnel.fragment.length,
                    "interval": tunnel.fragment.interval
                }
            }
        }));
    } else {
        outbounds.push(proxy_outbound);
    }

    outbounds.push(json!({ "protocol": "freedom", "tag": "direct" }));
    outbounds.push(json!({ "protocol": "blackhole", "tag": "block" }));

    let dns = json!({ "servers": dns_servers_for(&tunnel.dns) });

    // Адреса из "Адреса в обход прокси" — всегда direct, независимо от per-app и обычных
    // routing_rules. Нормализуем то, что реально вводят пользователи: "*.ru" -> "domain:ru",
    // "yandex.ru/*" -> домен без хвоста пути, голый IP/CIDR — в ip-список.
    let bypass_rules: Vec<Value> = tunnel
        .bypass_addresses
        .iter()
        .map(|b| normalize_bypass_rule(&b.value))
        .collect();

    let routing_rules: Vec<Value> = tunnel
        .routing_rules
        .iter()
        .map(|r| {
            let tag = match r.action.as_str() {
                "direct" => "direct",
                "block" => "block",
                _ => "proxy",
            };
            // value уже в родном синтаксисе xray-core (домен / IP-CIDR / geosite:xx / geoip:xx),
            // поэтому просто решаем, в какое поле его класть, по префиксу.
            if r.value.starts_with("geoip:") || r.value.contains('/') || r.value.parse::<std::net::IpAddr>().is_ok() {
                json!({ "type": "field", "ip": [r.value], "outboundTag": tag })
            } else {
                json!({ "type": "field", "domain": [normalize_domain_value(&r.value)], "outboundTag": tag })
            }
        })
        .collect();

    // Правило для Stats API должно идти первым — иначе его перехватит более общее правило
    // маршрутизации, и xray api statsquery перестанет получать ответ.
    let mut all_rules = vec![json!({
        "type": "field",
        "inboundTag": ["api-in"],
        "outboundTag": "api"
    })];
    all_rules.extend(bypass_rules);
    all_rules.extend(routing_rules);

    // Правила по доменам работают только если ядро видит имя сайта. Поэтому сниффинг включается
    // сам, как только есть правила маршрутизации или адреса в обход (даже если выключен в настройках).
    let sniffing_on = tunnel.sniffing_enabled || !tunnel.routing_rules.is_empty() || !tunnel.bypass_addresses.is_empty();
    let sniffing = json!({ "enabled": sniffing_on, "destOverride": ["http", "tls", "quic"] });

    Ok(json!({
        "log": { "loglevel": "warning" },
        "api": { "tag": "api", "services": ["StatsService"] },
        "stats": {},
        "policy": {
            "system": { "statsOutboundUplink": true, "statsOutboundDownlink": true }
        },
        "dns": dns,
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": { "udp": true },
                "sniffing": sniffing
            },
            {
                "listen": "127.0.0.1",
                "port": HTTP_PORT,
                "protocol": "http",
                "sniffing": sniffing
            },
            {
                "listen": "127.0.0.1",
                "port": API_PORT,
                "protocol": "dokodemo-door",
                "settings": { "address": "127.0.0.1" },
                "tag": "api-in"
            }
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": all_rules
        }
    }))
}

pub(crate) fn dns_servers_for(dns: &crate::config::DnsSettings) -> Vec<String> {
    match dns.mode.as_str() {
        "google" => vec!["8.8.8.8".into(), "8.8.4.4".into()],
        "cloudflare" => vec!["1.1.1.1".into(), "1.0.0.1".into()],
        "quad9" => vec!["9.9.9.9".into(), "149.112.112.112".into()],
        "custom" if !dns.servers.is_empty() => dns.servers.clone(),
        _ => vec!["1.1.1.1".into(), "8.8.8.8".into()], // "cloudflare_google" и дефолт
    }
}

fn normalize_bypass_rule(raw: &str) -> Value {
    let cleaned = raw.trim().trim_end_matches("/*").trim_start_matches("*.");

    if cleaned.parse::<std::net::IpAddr>().is_ok() || cleaned.contains('/') {
        json!({ "type": "field", "ip": [cleaned], "outboundTag": "direct" })
    } else {
        json!({ "type": "field", "domain": [format!("domain:{cleaned}")], "outboundTag": "direct" })
    }
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            (
                k.to_string(),
                urlencoding::decode(v).map(|c| c.into_owned()).unwrap_or_default(),
            )
        })
        .collect()
}

pub(crate) fn build_outbound(server: &VpnServer) -> Result<Value, String> {
    if server.raw_link.trim_start().starts_with('{') {
        return json_outbound(server);
    }
    match server.protocol.as_str() {
        "vless" => build_vless_outbound(server),
        "trojan" => build_trojan_outbound(server),
        "vmess" => build_vmess_outbound(server),
        "shadowsocks" => build_ss_outbound(server),
        other => Err(format!("протокол {other} пока не поддержан")),
    }
}

fn split_link_parts(link: &str, scheme_len: usize) -> (String, String, u16, std::collections::HashMap<String, String>) {
    let rest = &link[scheme_len..];
    let (body, _name) = split_fragment(rest);
    let at_pos = body.find('@').unwrap_or(0);
    let userinfo = body[..at_pos].to_string();
    let host_port_query = &body[at_pos + 1..];
    let (host_port, query) = host_port_query.split_once('?').unwrap_or((host_port_query, ""));
    let (host, port_str) = host_port.rsplit_once(':').unwrap_or((host_port, "443"));
    let port: u16 = port_str.parse().unwrap_or(443);
    (userinfo, host.to_string(), port, parse_query(query))
}

fn build_vless_outbound(server: &VpnServer) -> Result<Value, String> {
    let (uuid, host, port, q) = split_link_parts(&server.raw_link, "vless://".len());
    let security = q.get("security").cloned().unwrap_or_default();
    let network = q.get("type").cloned().unwrap_or_else(|| "tcp".into());

    let mut stream_settings = json!({ "network": network });

    if security == "reality" {
        stream_settings["security"] = json!("reality");
        stream_settings["realitySettings"] = json!({
            "serverName": q.get("sni").cloned().unwrap_or_default(),
            "fingerprint": q.get("fp").cloned().unwrap_or_else(|| "chrome".into()),
            "publicKey": q.get("pbk").cloned().unwrap_or_default(),
            "shortId": q.get("sid").cloned().unwrap_or_default(),
        });
    } else if security == "tls" {
        stream_settings["security"] = json!("tls");
        stream_settings["tlsSettings"] = json!({
            "serverName": q.get("sni").cloned().unwrap_or_else(|| host.clone()),
        });
    }

    if network == "ws" {
        stream_settings["wsSettings"] = json!({
            "path": q.get("path").cloned().unwrap_or_else(|| "/".into()),
            "headers": { "Host": q.get("host").cloned().unwrap_or_else(|| host.clone()) }
        });
    }

    Ok(json!({
        "protocol": "vless",
        "tag": "proxy",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{ "id": uuid, "encryption": "none", "flow": q.get("flow").cloned().unwrap_or_default() }]
            }]
        },
        "streamSettings": stream_settings
    }))
}

fn build_trojan_outbound(server: &VpnServer) -> Result<Value, String> {
    let (password, host, port, q) = split_link_parts(&server.raw_link, "trojan://".len());
    let security = q.get("security").cloned().unwrap_or_else(|| "tls".into());

    let mut stream_settings = json!({ "network": q.get("type").cloned().unwrap_or_else(|| "tcp".into()) });
    if security != "none" {
        stream_settings["security"] = json!("tls");
        stream_settings["tlsSettings"] = json!({
            "serverName": q.get("sni").cloned().unwrap_or_else(|| host.clone()),
        });
    }

    Ok(json!({
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "servers": [{ "address": host, "port": port, "password": password }]
        },
        "streamSettings": stream_settings
    }))
}

fn build_vmess_outbound(server: &VpnServer) -> Result<Value, String> {
    let b64 = server.raw_link.strip_prefix("vmess://").unwrap_or("");
    let decoded = STANDARD
        .decode(b64.trim())
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&decoded).map_err(|e| e.to_string())?;

    let host = v["add"].as_str().unwrap_or("").to_string();
    let port: u16 = v["port"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v["port"].as_u64().map(|p| p as u16))
        .unwrap_or(443);
    let uuid = v["id"].as_str().unwrap_or("").to_string();
    let aid: u32 = v["aid"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
    let network = v["net"].as_str().unwrap_or("tcp").to_string();
    let tls = v["tls"].as_str().unwrap_or("");

    let mut stream_settings = json!({ "network": network });
    if tls == "tls" {
        stream_settings["security"] = json!("tls");
        stream_settings["tlsSettings"] = json!({
            "serverName": v["sni"].as_str().unwrap_or(&host),
        });
    }
    if network == "ws" {
        stream_settings["wsSettings"] = json!({
            "path": v["path"].as_str().unwrap_or("/"),
            "headers": { "Host": v["host"].as_str().unwrap_or(&host) }
        });
    }

    Ok(json!({
        "protocol": "vmess",
        "tag": "proxy",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{ "id": uuid, "alterId": aid, "security": "auto" }]
            }]
        },
        "streamSettings": stream_settings
    }))
}

fn build_ss_outbound(server: &VpnServer) -> Result<Value, String> {
    let rest = server.raw_link.strip_prefix("ss://").unwrap_or("");
    let (body, _name) = split_fragment(rest);

    let (method_password, host, port) = if let Some(at_pos) = body.find('@') {
        let mp = STANDARD
            .decode(&body[..at_pos])
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let host_port = body[at_pos + 1..].split('?').next().unwrap_or("");
        let (h, p) = host_port.rsplit_once(':').unwrap_or((host_port, "8388"));
        (mp, h.to_string(), p.parse().unwrap_or(8388u16))
    } else {
        let decoded = STANDARD
            .decode(body)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let (mp, host_part) = decoded.split_once('@').unwrap_or(("", ""));
        let (h, p) = host_part.rsplit_once(':').unwrap_or((host_part, "8388"));
        (mp.to_string(), h.to_string(), p.parse().unwrap_or(8388u16))
    };

    let (method, password) = method_password.split_once(':').unwrap_or(("aes-256-gcm", ""));

    Ok(json!({
        "protocol": "shadowsocks",
        "tag": "proxy",
        "settings": {
            "servers": [{ "address": host, "port": port, "method": method, "password": password }]
        }
    }))
}

/// -------- Управление процессами VPN (xray / sing-box / tun2proxy) --------

const MAX_LOG_LINES: usize = 400;

pub struct VpnManager {
    /// Основной процесс: xray (proxy / xray-tun / tun2proxy) или sing-box (singbox / adaptive).
    child: Mutex<Option<Child>>,
    /// Дополнительный процесс — tun2proxy поверх xray.
    extra: Mutex<Option<Child>>,
    resources_dir: PathBuf,
    logs: std::sync::Arc<Mutex<std::collections::VecDeque<String>>>,
    mode: Mutex<crate::tun_mode::VpnMode>,
    plan: Mutex<Option<crate::tun_mode::AdaptivePlan>>,
    /// Сериализует connect/stop. Без этого два пересёкшихся подключения (двойной клик, трей +
    /// окно, переподключение после смены настроек) оба проходили stop(), оба запускали ядро,
    /// и второй процесс затирал в `child` дескриптор первого — первый оставался жить без
    /// хозяина: порты заняты, TUN-адаптер на месте, остановить его из приложения нечем.
    op: Mutex<()>,
}

/// Ждёт, пока на 127.0.0.1:port начнут принимать соединения.
fn wait_port(port: u16, timeout: std::time::Duration) -> bool {
    use std::net::{SocketAddr, TcpStream};
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    false
}

impl VpnManager {
    pub fn new(resources_dir: PathBuf) -> Self {
        Self {
            child: Mutex::new(None),
            extra: Mutex::new(None),
            resources_dir,
            logs: std::sync::Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(MAX_LOG_LINES))),
            mode: Mutex::new(crate::tun_mode::VpnMode::Proxy),
            plan: Mutex::new(None),
            op: Mutex::new(()),
        }
    }

    pub fn set_mode(&self, mode: crate::tun_mode::VpnMode) {
        *self.mode.lock().unwrap() = mode;
    }

    pub fn mode(&self) -> crate::tun_mode::VpnMode {
        *self.mode.lock().unwrap()
    }

    pub fn set_plan(&self, plan: Option<crate::tun_mode::AdaptivePlan>) {
        *self.plan.lock().unwrap() = plan;
    }

    pub fn plan(&self) -> Option<crate::tun_mode::AdaptivePlan> {
        self.plan.lock().unwrap().clone()
    }

    fn xray_path(&self) -> PathBuf {
        self.resources_dir.join("xray").join("xray.exe")
    }

    /// Реально ли жив основной процесс (а не просто "мы его когда-то запускали") —
    /// иначе интерфейс показывал бы "подключено", когда ядро уже упало на кривом конфиге.
    pub fn is_running(&self) -> bool {
        let mut guard = self.child.lock().unwrap();
        match guard.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    pub fn recent_logs(&self) -> Vec<String> {
        self.logs.lock().unwrap().iter().cloned().collect()
    }

    fn push_log(logs: &std::sync::Arc<Mutex<std::collections::VecDeque<String>>>, line: String) {
        let mut l = logs.lock().unwrap();
        if l.len() >= MAX_LOG_LINES {
            l.pop_front();
        }
        l.push_back(line);
    }

    /// Останавливает всё, что запущено. Корректно (Ctrl+C), а не убийством: TUN-ядра при
    /// штатном завершении сами удаляют адаптер и откатывают маршруты. Сначала tun2proxy
    /// (он правил маршруты поверх xray), потом основной процесс, затем подметаются
    /// осиротевшие процессы ядер.
    pub fn stop(&self) {
        let _op = self.op.lock().unwrap();
        self.stop_locked();
    }

    /// То же без захвата `op` — для вызовов изнутри connect(), где блокировка уже держится.
    fn stop_locked(&self) {
        let wait = std::time::Duration::from_secs(4);
        // Процесс сначала вынимается из мьютекса отдельным выражением: иначе гард жил бы
        // всё время ожидания (до 4с) и блокировал is_running(), который UI опрашивает
        // каждые пару секунд.
        let extra = self.extra.lock().unwrap().take();
        if let Some(mut c) = extra {
            crate::proc_util::graceful_stop(&mut c, wait);
        }
        let main = self.child.lock().unwrap().take();
        if let Some(mut c) = main {
            crate::proc_util::graceful_stop(&mut c, wait);
        }
        self.sweep_orphans();
    }

    /// Добивает процессы ядер (xray / sing-box / tun2proxy), запущенные из наших папок, но не
    /// принадлежащие ни одному `Child`: остались от прошлого сеанса (приложение убили через
    /// диспетчер задач, оно упало) или потеряли дескриптор. Вызывать только когда собственные
    /// процессы уже остановлены — всё найденное лишнее. Ядра просят завершиться по Ctrl+C, чтобы
    /// TUN-адаптер и маршруты откатились штатно.
    pub fn sweep_orphans(&self) {
        let r = &self.resources_dir;
        crate::process_monitor::sweep_many(
            &[
                ("xray.exe", r.join("xray")),
                ("sing-box.exe", r.join("singbox")),
                ("tun2proxy-bin.exe", r.join("tun2proxy")),
            ],
            Some(std::time::Duration::from_secs(3)),
        );
    }

    /// Запускает процесс с перехватом stdout/stderr в общий лог. Без вычитывания пайпов
    /// дочерний процесс со временем зависает (переполнение буфера ОС).
    /// `tag` — префикс строк лога; `mark_stderr` — помечать ли строки stderr (xray пишет
    /// туда ошибки, а sing-box — вообще весь свой лог, его красить красным незачем).
    fn spawn_logged(&self, cmd: &mut Command, tag: &str, mark_stderr: bool) -> Result<Child, String> {
        // stdin обязательно null: унаследованный stdin у GUI-процесса после AttachConsole/
        // FreeConsole содержит мёртвый дескриптор и даёт "Неверный дескриптор (os error 6)".
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW | ABOVE_NORMAL_PRIORITY_CLASS);
        let mut child = cmd.spawn().map_err(|e| {
            let name = cmd.get_program().to_string_lossy().to_string();
            format!("не удалось запустить {name}: {e}")
        })?;

        use std::io::{BufRead, BufReader};
        let prefix = if tag.is_empty() { String::new() } else { format!("[{tag}] ") };

        if let Some(stdout) = child.stdout.take() {
            let logs = self.logs.clone();
            let prefix = prefix.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().flatten() {
                    Self::push_log(&logs, format!("{prefix}{line}"));
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let logs = self.logs.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().flatten() {
                    let line = if mark_stderr { format!("[stderr] {prefix}{line}") } else { format!("{prefix}{line}") };
                    Self::push_log(&logs, line);
                }
            });
        }
        Ok(child)
    }

    /// Даёт процессу время стартовать и, если он сразу умер (кривой конфиг, нет прав,
    /// старая версия ядра без нужной фичи), возвращает ошибку с последними строками лога —
    /// вместо молчаливого "подключено", при котором интернета просто нет.
    fn fail_if_dead(&self, label: &str) -> Result<(), String> {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let dead = {
            let mut guard = self.child.lock().unwrap();
            match guard.as_mut() {
                Some(c) => !matches!(c.try_wait(), Ok(None)),
                None => true,
            }
        };
        if dead {
            std::thread::sleep(std::time::Duration::from_millis(200)); // дочитать хвост лога
            let tail: Vec<String> = self.recent_logs().into_iter().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
            self.stop_locked();
            return Err(format!("{label} завершился сразу после запуска:\n{}", tail.join("\n")));
        }
        Ok(())
    }

    fn start_xray(&self, config: Value) -> Result<(), String> {
        let config_path = std::env::temp_dir().join("zapret-unified-xray.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap())
            .map_err(|e| e.to_string())?;

        let mut cmd = Command::new(self.xray_path());
        cmd.arg("run").arg("-config").arg(&config_path);
        let child = self.spawn_logged(&mut cmd, "", true)?;
        *self.child.lock().unwrap() = Some(child);
        Ok(())
    }

    pub fn connect(&self, server: &VpnServer, tunnel: &crate::config::TunnelSettings) -> Result<(), String> {
        use crate::tun_mode::{self, VpnMode};

        // Вся операция подключения — под одной блокировкой (см. поле `op`).
        let _op = self.op.lock().unwrap();
        self.stop_locked();
        self.logs.lock().unwrap().clear();

        match self.mode() {
            VpnMode::Proxy => {
                self.start_xray(build_xray_config(server, tunnel)?)?;
                Ok(())
            }

            VpnMode::XrayTun => {
                tun_mode::place_wintun(&self.resources_dir, &self.resources_dir.join("xray"))?;
                self.start_xray(tun_mode::build_xray_tun_config(server, tunnel)?)?;
                self.fail_if_dead("xray (TUN)")
            }

            VpnMode::Tun2Proxy => {
                let (host, port) = server_endpoint(server)?;
                let ips = tun_mode::resolve_server_ips(&host, port);
                if ips.is_empty() {
                    return Err(format!("не удалось определить IP сервера {host} — нужен для --bypass"));
                }

                self.start_xray(build_xray_config(server, tunnel)?)?;
                if !wait_port(SOCKS_PORT, std::time::Duration::from_secs(5)) {
                    self.stop_locked();
                    return Err("xray не открыл локальный SOCKS-порт — смотрите логи".into());
                }

                let tdir = self.resources_dir.join("tun2proxy");
                tun_mode::place_wintun(&self.resources_dir, &tdir)?;

                let mut cmd = Command::new(tdir.join("tun2proxy-bin.exe"));
                cmd.current_dir(&tdir)
                    .arg("--proxy")
                    .arg(format!("socks5://127.0.0.1:{SOCKS_PORT}"))
                    .arg("--setup");
                for ip in &ips {
                    cmd.arg("--bypass").arg(ip);
                }
                let child = self.spawn_logged(&mut cmd, "tun2proxy", false)?;
                *self.extra.lock().unwrap() = Some(child);

                std::thread::sleep(std::time::Duration::from_millis(1500));
                let extra_dead = {
                    let mut g = self.extra.lock().unwrap();
                    g.as_mut().map(|c| !matches!(c.try_wait(), Ok(None))).unwrap_or(true)
                };
                if extra_dead {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let tail: Vec<String> = self.recent_logs().into_iter().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
                    self.stop_locked();
                    return Err(format!("tun2proxy завершился сразу после запуска:\n{}", tail.join("\n")));
                }
                Ok(())
            }

            m @ (VpnMode::SingBox | VpnMode::Adaptive) => {
                let plan = if m == VpnMode::Adaptive { self.plan() } else { None };
                let config = tun_mode::build_singbox_config(server, tunnel, plan.as_ref())?;

                let sdir = self.resources_dir.join("singbox");
                tun_mode::place_wintun(&self.resources_dir, &sdir)?;

                let config_path = std::env::temp_dir().join("zapret-unified-singbox.json");
                std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap())
                    .map_err(|e| e.to_string())?;

                let mut cmd = Command::new(sdir.join("sing-box.exe"));
                cmd.current_dir(&sdir).arg("run").arg("-c").arg(&config_path);
                let child = self.spawn_logged(&mut cmd, "", false)?;
                *self.child.lock().unwrap() = Some(child);

                self.fail_if_dead("sing-box")
            }
        }
    }
}

/// TCP-пинг до сервера — время установки соединения, как "Тест задержки" в INCY/аналогах.
/// Не идёт через сам туннель (это было бы задержкой уже после подключения) — меряет чистую
/// сетевую доступность хоста, что и нужно для выбора сервера до коннекта.
pub async fn ping_host_async(host: String, port: u16) -> Option<u128> {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration, Instant};

    let start = Instant::now();
    match timeout(Duration::from_secs(4), TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(_)) => Some(start.elapsed().as_millis()),
        _ => None,
    }
}

/// Извлекает host:port сервера из уже собранного outbound-JSON — используется, чтобы не
/// дублировать парсинг ссылки только ради пинга.
pub fn server_endpoint(server: &VpnServer) -> Result<(String, u16), String> {
    let outbound = build_outbound(server)?;
    if let Some(vnext) = outbound["settings"]["vnext"].as_array().and_then(|a| a.first()) {
        let host = vnext["address"].as_str().unwrap_or_default().to_string();
        let port = vnext["port"].as_u64().unwrap_or(443) as u16;
        return Ok((host, port));
    }
    if let Some(srv) = outbound["settings"]["servers"].as_array().and_then(|a| a.first()) {
        let host = srv["address"].as_str().unwrap_or_default().to_string();
        let port = srv["port"].as_u64().unwrap_or(443) as u16;
        return Ok((host, port));
    }
    Err("не удалось определить адрес сервера".into())
}

#[derive(serde::Serialize, Clone, Debug, Default)]
pub struct StatsSnapshot {
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
}

/// Опрашивает Stats API запущенного xray.exe через его же CLI-подкоманду
/// `xray api statsquery` (родной способ xray-core, не требует отдельной gRPC-обвязки
/// в нашем коде). Работает только пока VPN подключён — иначе dokodemo-door на API_PORT
/// никто не поднимает.
pub fn query_stats(resources_dir: &PathBuf) -> Result<StatsSnapshot, String> {
    let xray_path = resources_dir.join("xray").join("xray.exe");
    let mut cmd = Command::new(xray_path);
    cmd.arg("api")
        .arg("statsquery")
        .arg(format!("-server=127.0.0.1:{API_PORT}"));
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd
        .output()
        .map_err(|e| format!("не удалось опросить xray api: {e}"))?;

    let text = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("некорректный ответ api: {e}"))?;

    let mut snap = StatsSnapshot::default();
    if let Some(stats) = parsed["stat"].as_array() {
        for s in stats {
            let name = s["name"].as_str().unwrap_or_default();
            let value = s["value"].as_u64().unwrap_or(0);
            if name.contains(">>>traffic>>>uplink") {
                snap.uplink_bytes += value;
            } else if name.contains(">>>traffic>>>downlink") {
                snap.downlink_bytes += value;
            }
        }
    }
    Ok(snap)
}

/// -------- Системный прокси Windows --------
/// Прописывает 127.0.0.1:HTTP_PORT как системный HTTP-прокси через реестр
/// (HKCU\...\Internet Settings) и уведомляет систему об изменении через WinINet API,
/// чтобы браузеры/приложения, читающие системные настройки, подхватили новый прокси
/// без перезагрузки. Это НЕ полноценный TUN-VPN уровня ядра (как в INCY) — трафик идёт
/// через системный HTTP/SOCKS прокси, что покрывает браузеры и большинство приложений,
/// но не гарантированно покрывает всё (некоторые приложения игнорируют системный прокси).
#[cfg(windows)]
mod wininet_ffi {
    use std::ffi::c_void;
    #[link(name = "wininet")]
    extern "system" {
        pub fn InternetSetOptionW(
            h_internet: *mut c_void,
            dw_option: u32,
            lp_buffer: *mut c_void,
            dw_buffer_length: u32,
        ) -> i32;
    }
    pub const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    pub const INTERNET_OPTION_REFRESH: u32 = 37;
}

#[cfg(windows)]
pub fn set_system_proxy(enable: bool) -> anyhow::Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    )?;

    key.set_value("ProxyEnable", &(if enable { 1u32 } else { 0u32 }))?;
    if enable {
        key.set_value("ProxyServer", &format!("127.0.0.1:{HTTP_PORT}"))?;
    }

    unsafe {
        wininet_ffi::InternetSetOptionW(
            std::ptr::null_mut(),
            wininet_ffi::INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        wininet_ffi::InternetSetOptionW(
            std::ptr::null_mut(),
            wininet_ffi::INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn set_system_proxy(_enable: bool) -> anyhow::Result<()> {
    Ok(())
}

/// -------- Per-app proxy (без TUN) --------
/// Настоящий системный TUN-адаptер per-app не делаем (см. README) — вместо этого перезапускаем
/// целевые Chromium-приложения (chrome/edge/brave/opera/vivaldi) и Discord (тоже Electron/
/// Chromium под капотом) с флагом --proxy-server=... или --no-proxy-server. Это официальный
/// флаг Chromium, тем же приёмом пользуются десктопные "переключатели прокси".
/// Ограничение: Firefox так не переключить (нет такого CLI-флага у Gecko) — придётся вручную
/// через about:config/сетевые настройки.
pub fn apply_per_app(settings: &crate::config::PerAppSettings) -> Result<(), String> {
    if !settings.enabled || settings.apps.is_empty() {
        return Ok(());
    }

    let proxy_flag = format!("--proxy-server=socks5://127.0.0.1:{SOCKS_PORT}");

    for app in &settings.apps {
        if app.eq_ignore_ascii_case("firefox.exe") {
            continue; // осознанно пропускаем, см. комментарий выше
        }

        let exe_path = crate::process_monitor::find_exe_path(app);
        crate::process_monitor::kill_by_name(app);

        // Даём процессу время реально завершиться, прежде чем поднимать заново —
        // иначе новый экземпляр может тут же слиться со старым (Chromium single-instance).
        std::thread::sleep(std::time::Duration::from_millis(700));

        if let Some(path) = exe_path {
            let flag = if settings.mode == "bypass" {
                "--no-proxy-server"
            } else {
                proxy_flag.as_str()
            };
            let _ = Command::new(path)
                .arg(flag)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
    }

    Ok(())
}

/// -------- HWID и загрузка подписки --------
/// HWID нужен панелям (Marzban/Remnawave и т.п.), которые привязывают выданный ключ к
/// конкретному устройству. Берём стабильный, но не содержащий личных данных источник —
/// MachineGuid из реестра (генерируется Windows при установке ОС, не меняется между
/// перезагрузками) — и хешируем его, чтобы не светить сырой системный идентификатор
/// в HTTP-заголовках напрямую.
#[cfg(windows)]
pub fn compute_hwid() -> String {
    use sha2::{Digest, Sha256};
    use winreg::enums::*;
    use winreg::RegKey;

    let raw = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .and_then(|k| k.get_value::<String, _>("MachineGuid"))
        .unwrap_or_else(|_| "unknown-machine".into());

    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(not(windows))]
pub fn compute_hwid() -> String {
    "unsupported-platform".into()
}

// ---------------------------------------------------------------------------------------
// Метаданные сервера (теги в интерфейсе) и JSON-конфиги
// ---------------------------------------------------------------------------------------

/// Заполняет теги, которые показывает интерфейс: формат (LINK/JSON), транспорт (TCP/WS/…) и
/// защиту (REALITY/TLS). Источник правды — тот же собранный outbound, с которым реально
/// запускается ядро, поэтому тег не может расходиться с тем, что будет работать.
pub fn fill_meta(server: &mut VpnServer) {
    server.format = if server.raw_link.trim_start().starts_with('{') {
        "JSON".to_string()
    } else {
        "LINK".to_string()
    };
    if let Ok(ob) = build_outbound(server) {
        let ss = &ob["streamSettings"];
        server.transport = ss["network"].as_str().unwrap_or("tcp").to_uppercase();
        server.security = match ss["security"].as_str() {
            Some("reality") => "REALITY",
            Some("tls") => "TLS",
            _ => "",
        }
        .to_string();
    }
}

/// Новые версии xray допускают "плоский" settings (`{address, port, id, ...}` вместо
/// `vnext[]`/`servers[]`). Приводим к классическому виду, который понимают
/// build_xray_config и конвертер в sing-box.
fn normalize_json_outbound(mut ob: Value) -> Value {
    let proto = ob["protocol"].as_str().unwrap_or("").to_string();
    let settings = ob["settings"].clone();
    let flat = settings.get("address").is_some();

    match proto.as_str() {
        "vless" if settings.get("vnext").is_none() && flat => {
            ob["settings"] = json!({ "vnext": [{
                "address": settings["address"],
                "port": settings["port"],
                "users": [{
                    "id": settings["id"],
                    "encryption": settings.get("encryption").cloned().unwrap_or(json!("none")),
                    "flow": settings.get("flow").cloned().unwrap_or(json!(""))
                }]
            }]});
        }
        "vmess" if settings.get("vnext").is_none() && flat => {
            ob["settings"] = json!({ "vnext": [{
                "address": settings["address"],
                "port": settings["port"],
                "users": [{
                    "id": settings["id"],
                    "alterId": settings.get("alterId").cloned().unwrap_or(json!(0)),
                    "security": settings.get("security").cloned().unwrap_or(json!("auto"))
                }]
            }]});
        }
        "trojan" | "shadowsocks" if settings.get("servers").is_none() && flat => {
            ob["settings"] = json!({ "servers": [settings] });
        }
        _ => {}
    }
    ob
}

/// outbound из JSON-записи сервера (формат JSON): готовый xray-outbound, как его отдаёт
/// панель подписки. Тег всегда "proxy" — на него ссылаются остальные части конфига.
fn json_outbound(server: &VpnServer) -> Result<Value, String> {
    let ob: Value = serde_json::from_str(&server.raw_link)
        .map_err(|e| format!("битый JSON сервера «{}»: {e}", server.name))?;
    let mut ob = normalize_json_outbound(ob);
    ob["tag"] = json!("proxy");
    Ok(ob)
}

fn is_proxy_outbound(o: &Value) -> bool {
    matches!(
        o["protocol"].as_str(),
        Some("vless" | "vmess" | "trojan" | "shadowsocks")
    )
}

/// Серверы из JSON, вставленного пользователем: либо один outbound ({"protocol": ...}), либо полный
/// конфиг xray / список конфигов. Возвращает все найденные прокси-подключения.
pub fn parse_json_servers(text: &str) -> Result<Vec<VpnServer>, String> {
    let t = text.trim();
    let root: Value = serde_json::from_str(t).map_err(|e| format!("некорректный JSON: {e}"))?;
    let mut servers: Vec<VpnServer> = if root.is_object() && root.get("protocol").is_some() {
        if !is_proxy_outbound(&root) {
            return Err("в JSON не найдено прокси-подключение (vless, vmess, trojan или shadowsocks)".into());
        }
        let name = root["remarks"]
            .as_str()
            .or(root["tag"].as_str())
            .unwrap_or_else(|| root["protocol"].as_str().unwrap_or("server"))
            .to_string();
        vec![VpnServer {
            id: new_id("srv"),
            name,
            protocol: root["protocol"].as_str().unwrap_or("").to_string(),
            raw_link: normalize_json_outbound(root.clone()).to_string(),
            ..Default::default()
        }]
    } else {
        parse_json_subscription(t)
    };
    if servers.is_empty() {
        return Err("в JSON не найдено прокси-подключение (vless, vmess, trojan или shadowsocks)".into());
    }
    for s in servers.iter_mut() {
        fill_meta(s);
    }
    Ok(servers)
}

/// Подписка в формате xray-JSON: массив (или один объект) полных конфигов с `remarks` и
/// `outbounds`. Из каждого берём первый прокси-outbound (приоритет — у тега "proxy").
/// ВАЖНО: конфиги с балансировщиком (`routing.balancers` из нескольких outbound) целиком
/// мы не исполняем — подключаемся к первому узлу балансировщика, а не ко всей группе.
fn parse_json_subscription(text: &str) -> Vec<VpnServer> {
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        return vec![];
    };
    let items: Vec<Value> = match root {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v],
        _ => vec![],
    };

    let mut out = Vec::new();
    for item in items {
        let name_hint = ["remarks", "remark", "ps", "name"]
            .iter()
            .find_map(|k| item[*k].as_str())
            .map(String::from);

        let Some(outbounds) = item["outbounds"].as_array() else {
            continue;
        };
        let chosen = outbounds
            .iter()
            .find(|o| is_proxy_outbound(o) && o["tag"].as_str() == Some("proxy"))
            .or_else(|| outbounds.iter().find(|o| is_proxy_outbound(o)));
        let Some(ob) = chosen else { continue };

        let ob = normalize_json_outbound(ob.clone());
        let protocol = ob["protocol"].as_str().unwrap_or("").to_string();
        let name = name_hint
            .or_else(|| ob["tag"].as_str().map(String::from))
            .unwrap_or_else(|| protocol.clone());

        out.push(VpnServer {
            id: new_id("srv"),
            name,
            protocol,
            raw_link: ob.to_string(),
            ..Default::default()
        });
    }
    out
}

// ---------------------------------------------------------------------------------------
// Подписки
// ---------------------------------------------------------------------------------------

/// Результат загрузки подписки: серверы + метаданные из заголовков ответа.
pub struct FetchedSubscription {
    pub servers: Vec<VpnServer>,
    pub title: Option<String>,
    pub interval_hours: Option<u32>,
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire: i64,
    pub support_url: Option<String>,
    pub web_page_url: Option<String>,
    pub announce: Option<String>,
}

/// Значение заголовка как текст. Панели кладут в заголовки сырой UTF-8 (кириллица в названии)
/// — `to_str()` у reqwest на таких значениях падает, поэтому читаем байты сами. Префикс
/// `base64:` (так панели прячут не-ASCII) раскодируем.
fn header_text(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    let raw = String::from_utf8_lossy(headers.get(name)?.as_bytes()).trim().to_string();
    if raw.is_empty() {
        return None;
    }
    if let Some(b64) = raw.strip_prefix("base64:") {
        if let Ok(bytes) = STANDARD.decode(b64.trim()) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text.trim().to_string());
            }
        }
    }
    if raw.contains('%') {
        if let Ok(decoded) = urlencoding::decode(&raw) {
            return Some(decoded.into_owned());
        }
    }
    Some(raw)
}

/// `subscription-userinfo: upload=1; download=2; total=3; expire=4` — стандартный заголовок
/// панелей (Marzban, Remnawave, 3x-ui…). Числа иногда приходят в экспоненциальной записи.
fn parse_userinfo(v: &str) -> (u64, u64, u64, i64) {
    let mut out = (0u64, 0u64, 0u64, 0i64);
    for part in v.split(';') {
        let Some((k, val)) = part.split_once('=') else { continue };
        let val = val.trim();
        let num = val
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .unwrap_or(0.0);
        match k.trim() {
            "upload" => out.0 = num as u64,
            "download" => out.1 = num as u64,
            "total" => out.2 = num as u64,
            "expire" => out.3 = num as i64,
            _ => {}
        }
    }
    out
}

fn filename_from_disposition(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let v = header_text(headers, "content-disposition")?;
    let lower = v.to_ascii_lowercase();
    let idx = lower.find("filename=")?;
    let name = v[idx + "filename=".len()..]
        .split(';')
        .next()?
        .trim()
        .trim_matches('"')
        .to_string();
    if name.is_empty() {
        return None;
    }
    Some(urlencoding::decode(&name).map(|c| c.into_owned()).unwrap_or(name))
}

/// Тело подписки: либо уже читаемое (ссылки по одной на строку / JSON), либо base64 целиком.
/// Панели присылают base64 и с переносами строк, и без выравнивающих "=", и в url-safe
/// алфавите — пробуем все варианты.
fn decode_subscription_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.contains("://") || trimmed.starts_with('[') || trimmed.starts_with('{') {
        return trimmed.to_string();
    }
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&compact) {
            if let Ok(text) = String::from_utf8(bytes) {
                return text;
            }
        }
    }
    trimmed.to_string()
}

#[cfg(windows)]
fn windows_version() -> String {
    use winreg::enums::*;
    use winreg::RegKey;
    let build: u32 = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
        .ok()
        .and_then(|k| k.get_value::<String, _>("CurrentBuild").ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if build >= 22000 { "11".into() } else { "10".into() }
}

#[cfg(not(windows))]
fn windows_version() -> String {
    "unknown".into()
}

/// Скачивает подписку и разбирает её: список серверов (ссылки vless/vmess/trojan/ss — голые
/// или в base64 — либо xray-JSON) и метаданные из заголовков ответа (название, интервал
/// обновления, трафик, срок, ссылки поддержки).
///
/// HWID-панели (Remnawave и др.) привязывают подписку к устройству и ждут не только X-HWID,
/// но и описание устройства — без него ответ пустой или 4xx. `user_agent` задаётся
/// пользователем: часть панелей выбирает формат ответа (ссылки или JSON) именно по нему.
pub async fn fetch_subscription(
    url: &str,
    send_hwid: bool,
    user_agent: Option<&str>,
) -> Result<FetchedSubscription, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = client
        .get(url)
        .header("User-Agent", user_agent.unwrap_or("zapret-unified"));
    if send_hwid {
        req = req
            .header("X-HWID", compute_hwid())
            .header("X-Device-OS", "Windows")
            .header("X-Ver-OS", windows_version())
            .header("X-Device-Model", "PC");
    }

    let resp = req.send().await.map_err(|e| format!("не удалось загрузить подписку: {e}"))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.map_err(|e| e.to_string())?;

    if !status.is_success() {
        let hint = if matches!(status.as_u16(), 401 | 403 | 429) {
            " (возможно, исчерпан лимит устройств по HWID или подписка отключена)"
        } else {
            ""
        };
        let snippet: String = body.trim().chars().take(160).collect();
        return Err(format!(
            "сервер подписки ответил {status}{hint}{}",
            if snippet.is_empty() { String::new() } else { format!(": {snippet}") }
        ));
    }

    let decoded = decode_subscription_body(&body);
    let mut servers = if decoded.starts_with('[') || decoded.starts_with('{') {
        parse_json_subscription(&decoded)
    } else {
        decoded
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| parse_link(l).ok())
            .collect()
    };
    for s in servers.iter_mut() {
        fill_meta(s);
    }
    if servers.is_empty() {
        return Err("в ответе нет ни одного распознанного сервера (поддерживаются ссылки \
            vless/vmess/trojan/ss и xray-JSON). Если панель выбирает формат по User-Agent — \
            укажите другой в «дополнительно» при добавлении подписки"
            .into());
    }

    let (upload, download, total, expire) = header_text(&headers, "subscription-userinfo")
        .map(|v| parse_userinfo(&v))
        .unwrap_or((0, 0, 0, 0));

    Ok(FetchedSubscription {
        servers,
        title: header_text(&headers, "profile-title").or_else(|| filename_from_disposition(&headers)),
        interval_hours: header_text(&headers, "profile-update-interval")
            .and_then(|v| v.trim().parse::<u32>().ok()),
        upload,
        download,
        total,
        expire,
        support_url: header_text(&headers, "support-url"),
        web_page_url: header_text(&headers, "profile-web-page-url"),
        announce: header_text(&headers, "announce"),
    })
}


/// Домен без префикса xray считает ключевым словом: "ru" совпадёт и с "ruby.org". Поэтому обычный
/// домен переводим в "domain:", который совпадает с самим доменом и всеми его поддоменами.
/// Уже заданные префиксы (domain:, full:, keyword:, regexp:, geosite:, ext:) не трогаем.
fn normalize_domain_value(v: &str) -> String {
    let v = v.trim().trim_start_matches("*.");
    const PREFIXES: [&str; 6] = ["domain:", "full:", "keyword:", "regexp:", "geosite:", "ext:"];
    if PREFIXES.iter().any(|p| v.starts_with(p)) {
        v.to_string()
    } else {
        format!("domain:{v}")
    }
}
