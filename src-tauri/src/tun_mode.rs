//! Режимы VPN поверх обычного proxy-режима: TUN на ядрах Xray / sing-box, связка
//! xray + tun2proxy и собственный адаптивный split-TUN.
//!
//! Что здесь НЕ делается намеренно: мы не пишем свой TCP/IP-стек. Разбор сырых пакетов,
//! пересборка TCP-потоков и работа с wintun — это тысячи строк, в которых легко ошибиться
//! так, что пользователь потеряет интернет целиком; зрелые ядра (sing-box, xray, tun2proxy)
//! делают это надёжнее. Наша собственная часть — политика маршрутизации (см. `calibrate`
//! и `build_singbox_config`): КУДА отправлять какой трафик.

use crate::config::{TunnelSettings, VpnServer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const TUN_NAME: &str = "zapret-tun";
pub const TUN_ADDR: &str = "172.19.0.1/30";
pub const TUN_MTU: u32 = 1400;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VpnMode {
    Proxy,
    XrayTun,
    SingBox,
    Tun2Proxy,
    Adaptive,
}

impl VpnMode {
    pub fn parse(s: &str) -> VpnMode {
        match s {
            "xray-tun" => VpnMode::XrayTun,
            "singbox" => VpnMode::SingBox,
            "tun2proxy" => VpnMode::Tun2Proxy,
            "adaptive" => VpnMode::Adaptive,
            _ => VpnMode::Proxy,
        }
    }

    pub fn is_tun(self) -> bool {
        self != VpnMode::Proxy
    }
}

// ---------------------------------------------------------------------------------------
// Адаптивный алгоритм
// ---------------------------------------------------------------------------------------
//
// "Adaptive split-TUN". В TUN попадает весь трафик, и каждое соединение проходит конвейер
// классификации (порядок = порядок правил в route.rules):
//
//   0. sniff + hijack-dns   — домен известен даже для голого TLS; каждый DNS-запрос
//                             перехвачен, чтобы его можно было решить по политике.
//   1. LAN / loopback        -> direct
//   2. правила пользователя  (bypass-адреса, routing-правила из tunnel.conf)
//   3. "провалившиеся"       -> proxy   (домены, которые при калибровке НЕ открылись напрямую)
//   4. "рабочие напрямую"    -> direct  (открылись напрямую — обычно потому, что zapret
//                             обходит DPI на физическом канале; гнать их в прокси — лишняя
//                             задержка и трата трафика сервера)
//   5. "домашние" домены     -> direct  (.ru/.su/.рф и крупные российские сервисы)
//   6. всё остальное         -> proxy
//
// Адаптивность — в пунктах 3-4. Они не зашиты списком, а определяются КАЛИБРОВКОЙ в момент
// подключения: набор доменов из hostlist-а zapret (+ несколько якорных) проверяется
// напрямую, параллельно. Если большая часть доменов из списка zapret открылась — весь
// класс считается "работает напрямую"; отдельные провалившиеся при этом всё равно уходят
// в прокси. Если не открылось почти ничего (zapret выключен или у провайдера другая
// блокировка) — класс целиком уходит в прокси. Результат кэшируется на 6 часов.
//
// DNS подчиняется той же классификации: домены "напрямую" резолвятся напрямую, остальные —
// через DoH поверх прокси (защита от подмены DNS у провайдера).

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AdaptivePlan {
    pub built_at: u64,
    pub direct: Vec<String>,
    pub proxy: Vec<String>,
    pub probed: usize,
    pub probed_ok: usize,
}

const ANCHORS: &[&str] = &[
    "youtube.com",
    "discord.com",
    "instagram.com",
    "facebook.com",
    "x.com",
    "t.me",
    "linkedin.com",
    "soundcloud.com",
];

/// Домены, которые считаем "домашними" без всякой калибровки.
const DOMESTIC_SUFFIXES: &[&str] = &[
    "ru",
    "su",
    "xn--p1ai",
    "yandex.net",
    "yandex.com",
    "yastatic.net",
    "vk.com",
    "vk.me",
    "vkuser.net",
    "userapi.com",
    "mycdn.me",
];

const PLAN_TTL_SECS: u64 = 6 * 60 * 60;
const MAX_LIST_DOMAINS: usize = 1500;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_path(resources_dir: &Path) -> PathBuf {
    resources_dir.join("adaptive_cache.json")
}

pub fn load_cached_plan(resources_dir: &Path) -> Option<AdaptivePlan> {
    let text = std::fs::read_to_string(cache_path(resources_dir)).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_plan(resources_dir: &Path, plan: &AdaptivePlan) {
    if let Ok(text) = serde_json::to_string(plan) {
        let _ = std::fs::write(cache_path(resources_dir), text);
    }
}

fn read_zapret_domains(resources_dir: &Path) -> Vec<String> {
    let path = resources_dir.join("zapret").join("lists").join("list-general.txt");
    let text = std::fs::read_to_string(path).unwrap_or_default();

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let d = line.trim().trim_start_matches("*.").to_lowercase();
        let valid = !d.is_empty()
            && !d.starts_with('#')
            && d.contains('.')
            && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if valid && seen.insert(d.clone()) {
            out.push(d);
        }
    }
    out
}

/// Параллельная проверка "открывается ли сайт напрямую" — дошло ли до HTTP-ответа
/// (то есть TLS-рукопожатие прошло). Системный прокси игнорируем: проверяем именно
/// прямой канал.
async fn probe_domains(domains: &[String]) -> Vec<(String, bool)> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(6))
        .build()
        .unwrap_or_default();

    let mut handles = Vec::with_capacity(domains.len());
    for d in domains {
        let c = client.clone();
        let d = d.clone();
        handles.push(tokio::spawn(async move {
            let ok = c.get(format!("https://{d}/")).send().await.is_ok();
            (d, ok)
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(r) = h.await {
            out.push(r);
        }
    }
    out
}

/// Калибровка адаптивного плана (см. описание алгоритма выше). `force` — игнорировать кэш.
pub async fn calibrate(resources_dir: &Path, force: bool) -> AdaptivePlan {
    if !force {
        if let Some(p) = load_cached_plan(resources_dir) {
            if now_secs().saturating_sub(p.built_at) < PLAN_TTL_SECS {
                return p;
            }
        }
    }

    let list = read_zapret_domains(resources_dir);

    let mut candidates: Vec<String> = ANCHORS.iter().map(|s| s.to_string()).collect();
    for d in list.iter() {
        if candidates.len() >= 28 {
            break;
        }
        if !candidates.contains(d) {
            candidates.push(d.clone());
        }
    }

    let results = probe_domains(&candidates).await;
    let probed = results.len();
    let probed_ok = results.iter().filter(|(_, ok)| *ok).count();

    let mut direct: Vec<String> = results.iter().filter(|(_, ok)| *ok).map(|(d, _)| d.clone()).collect();
    let proxy: Vec<String> = results.iter().filter(|(_, ok)| !*ok).map(|(d, _)| d.clone()).collect();

    // Вывод по классу: если открылось не меньше 60% проверенных доменов ИЗ СПИСКА zapret,
    // считаем, что весь список работает напрямую (zapret справляется), и переносим его
    // в direct целиком — кроме тех, что провалились поштучно.
    let in_list: Vec<&(String, bool)> = results.iter().filter(|(d, _)| list.contains(d)).collect();
    let class_ok = !in_list.is_empty()
        && in_list.iter().filter(|(_, ok)| *ok).count() * 100 >= in_list.len() * 60;
    if class_ok {
        for d in list.iter().take(MAX_LIST_DOMAINS) {
            if !proxy.contains(d) && !direct.contains(d) {
                direct.push(d.clone());
            }
        }
    }

    let plan = AdaptivePlan {
        built_at: now_secs(),
        direct,
        proxy,
        probed,
        probed_ok,
    };
    save_plan(resources_dir, &plan);
    plan
}

// ---------------------------------------------------------------------------------------
// Конфиг sing-box
// ---------------------------------------------------------------------------------------

fn is_ip_or_cidr(v: &str) -> bool {
    v.parse::<std::net::IpAddr>().is_ok()
        || (v.contains('/')
            && v.split('/').next().and_then(|a| a.parse::<std::net::IpAddr>().ok()).is_some())
}

/// Правило из tunnel.conf (синтаксис xray) -> правило sing-box. geoip:/geosite:/regexp:
/// вернут None: в sing-box 1.12+ встроенных geo-баз нет, а тянуть rule-set'ы с GitHub
/// на старте VPN (когда GitHub как раз может быть недоступен) — плохая идея.
fn user_rule_to_singbox(value: &str, action: &str) -> Option<Value> {
    let mut rule = if value.starts_with("geoip:")
        || value.starts_with("geosite:")
        || value.starts_with("regexp:")
    {
        return None;
    } else if is_ip_or_cidr(value) {
        json!({ "ip_cidr": [value] })
    } else if let Some(d) = value.strip_prefix("domain:") {
        json!({ "domain_suffix": [d] })
    } else if let Some(d) = value.strip_prefix("full:") {
        json!({ "domain": [d] })
    } else if let Some(d) = value.strip_prefix("keyword:") {
        json!({ "domain_keyword": [d] })
    } else {
        json!({ "domain_suffix": [value] })
    };

    match action {
        "block" => rule["action"] = json!("reject"),
        "direct" => rule["outbound"] = json!("direct"),
        _ => rule["outbound"] = json!("proxy"),
    }
    Some(rule)
}

fn bypass_to_singbox(raw: &str) -> Value {
    let cleaned = raw.trim().trim_end_matches("/*").trim_start_matches("*.");
    if is_ip_or_cidr(cleaned) {
        json!({ "ip_cidr": [cleaned], "outbound": "direct" })
    } else {
        json!({ "domain_suffix": [cleaned], "outbound": "direct" })
    }
}

/// Перевод уже собранного xray-outbound (общий для всех режимов источник правды о сервере)
/// в outbound sing-box — чтобы не писать второй парсер ссылок.
fn xray_outbound_to_singbox(ob: &Value) -> Result<Value, String> {
    let proto = ob["protocol"].as_str().unwrap_or("");
    let ss = &ob["streamSettings"];

    let mut out = match proto {
        "vless" => {
            let v = &ob["settings"]["vnext"][0];
            let u = &v["users"][0];
            let mut o = json!({
                "type": "vless",
                "tag": "proxy",
                "server": v["address"],
                "server_port": v["port"],
                "uuid": u["id"],
                "packet_encoding": "xudp"
            });
            if let Some(f) = u["flow"].as_str().filter(|f| !f.is_empty()) {
                o["flow"] = json!(f);
            }
            o
        }
        "vmess" => {
            let v = &ob["settings"]["vnext"][0];
            let u = &v["users"][0];
            json!({
                "type": "vmess",
                "tag": "proxy",
                "server": v["address"],
                "server_port": v["port"],
                "uuid": u["id"],
                "alter_id": u["alterId"],
                "security": "auto"
            })
        }
        "trojan" => {
            let s = &ob["settings"]["servers"][0];
            json!({
                "type": "trojan",
                "tag": "proxy",
                "server": s["address"],
                "server_port": s["port"],
                "password": s["password"]
            })
        }
        "shadowsocks" => {
            let s = &ob["settings"]["servers"][0];
            json!({
                "type": "shadowsocks",
                "tag": "proxy",
                "server": s["address"],
                "server_port": s["port"],
                "method": s["method"],
                "password": s["password"]
            })
        }
        other => return Err(format!("протокол {other} не поддержан в sing-box режиме")),
    };

    match ss["security"].as_str() {
        Some("tls") => {
            out["tls"] = json!({
                "enabled": true,
                "server_name": ss["tlsSettings"]["serverName"],
                "utls": { "enabled": true, "fingerprint": "chrome" }
            });
        }
        Some("reality") => {
            let r = &ss["realitySettings"];
            out["tls"] = json!({
                "enabled": true,
                "server_name": r["serverName"],
                "utls": {
                    "enabled": true,
                    "fingerprint": r["fingerprint"].as_str().unwrap_or("chrome")
                },
                "reality": {
                    "enabled": true,
                    "public_key": r["publicKey"],
                    "short_id": r["shortId"]
                }
            });
        }
        _ => {}
    }

    if ss["network"].as_str() == Some("ws") {
        out["transport"] = json!({
            "type": "ws",
            "path": ss["wsSettings"]["path"],
            "headers": { "Host": ss["wsSettings"]["headers"]["Host"] }
        });
    }

    Ok(out)
}

/// Конфиг sing-box с TUN-входом. `plan` задан только в адаптивном режиме.
/// Используются только форматы sing-box 1.12+ (новые DNS-серверы, route actions) —
/// старые (`sniff` в inbound, special outbounds dns/block, inet4_address) в 1.13-1.14
/// удалены, поэтому ядро скачивается всегда свежее.
pub fn build_singbox_config(
    server: &VpnServer,
    tunnel: &TunnelSettings,
    plan: Option<&AdaptivePlan>,
) -> Result<Value, String> {
    let xray_ob = crate::vpn_manager::build_outbound(server)?;
    let proxy_ob = xray_outbound_to_singbox(&xray_ob)?;

    let mut direct_domains: Vec<String> = Vec::new();

    let mut rules: Vec<Value> = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        json!({ "ip_is_private": true, "outbound": "direct" }),
    ];

    // Голосовой UDP Discord. Через VLESS весь UDP кодируется как xudp — то есть все UDP-потоки
    // мультиплексируются в ОДНО TCP-соединение, и под нагрузкой (speedtest, закачка) голос
    // встаёт в одну очередь с чужим трафиком и повторными передачами TCP: пинг прыгает до
    // сотен миллисекунд. Если Discord по итогам калибровки открывается напрямую (то есть
    // zapret его вытягивает), его голосовые порты — те же, что перехватывает zapret
    // (19294-19344, 50000-50100) — отправляем напрямую, мимо туннеля.
    let discord_direct = plan
        .map(|p| p.direct.iter().any(|d| d.contains("discord")))
        .unwrap_or(false);
    if discord_direct {
        rules.push(json!({
            "network": "udp",
            "port_range": ["19294:19344", "50000:50100"],
            "outbound": "direct"
        }));
    }

    for b in &tunnel.bypass_addresses {
        let rule = bypass_to_singbox(&b.value);
        if let Some(ds) = rule["domain_suffix"].as_array() {
            direct_domains.extend(ds.iter().filter_map(|d| d.as_str().map(String::from)));
        }
        rules.push(rule);
    }

    for r in &tunnel.routing_rules {
        if let Some(rule) = user_rule_to_singbox(&r.value, &r.action) {
            if r.action == "direct" {
                if let Some(ds) = rule["domain_suffix"].as_array() {
                    direct_domains.extend(ds.iter().filter_map(|d| d.as_str().map(String::from)));
                }
            }
            rules.push(rule);
        }
    }

    if let Some(plan) = plan {
        if !plan.proxy.is_empty() {
            rules.push(json!({ "domain_suffix": plan.proxy, "outbound": "proxy" }));
        }
        if !plan.direct.is_empty() {
            rules.push(json!({ "domain_suffix": plan.direct, "outbound": "direct" }));
            direct_domains.extend(plan.direct.iter().cloned());
        }
        rules.push(json!({ "domain_suffix": DOMESTIC_SUFFIXES, "outbound": "direct" }));
        direct_domains.extend(DOMESTIC_SUFFIXES.iter().map(|s| s.to_string()));
    }

    // QUIC (HTTP/3) для трафика, который идёт в прокси, отклоняем: браузер мгновенно откатится
    // на обычный TCP, у каждого соединения будет собственный поток. Иначе QUIC YouTube/Google/
    // Cloudflare-speedtest шёл бы тем же xudp-мультиплексом и забивал его целиком. Правило стоит
    // ПОСЛЕ правил "напрямую" — домены, которые идут мимо прокси, сохраняют QUIC.
    rules.push(json!({ "protocol": "quic", "action": "reject" }));

    // Удалённый DNS-сервер — первый IP из настроек пользователя (DoH поверх прокси).
    let remote_dns = crate::vpn_manager::dns_servers_for(&tunnel.dns)
        .into_iter()
        .find(|s| s.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or_else(|| "1.1.1.1".to_string());

    let mut dns_rules: Vec<Value> = Vec::new();
    if !direct_domains.is_empty() {
        dns_rules.push(json!({ "domain_suffix": direct_domains, "server": "dns-local" }));
    }

    Ok(json!({
        "log": { "level": "info", "timestamp": true },
        "dns": {
            "servers": [
                { "type": "https", "tag": "dns-local", "server": "1.1.1.1" },
                { "type": "https", "tag": "dns-remote", "server": remote_dns, "detour": "proxy" }
            ],
            "rules": dns_rules,
            "final": "dns-remote",
            "strategy": "ipv4_only"
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": TUN_NAME,
            "address": [TUN_ADDR],
            "mtu": TUN_MTU,
            "auto_route": true,
            "strict_route": true,
            "stack": "mixed"
        }],
        "outbounds": [
            proxy_ob,
            { "type": "direct", "tag": "direct" }
        ],
        "route": {
            "rules": rules,
            "final": "proxy",
            "auto_detect_interface": true,
            "default_domain_resolver": { "server": "dns-local" }
        }
    }))
}

// ---------------------------------------------------------------------------------------
// Конфиг Xray с TUN-входом
// ---------------------------------------------------------------------------------------

/// Обычный конфиг xray + inbound `tun` (wintun) с автоматической настройкой маршрутов.
/// `autoOutboundsInterface: auto` — аналог auto_detect_interface: исходящие соединения
/// xray привязываются к физическому интерфейсу, иначе трафик самого xray до сервера снова
/// попадал бы в TUN (петля).
pub fn build_xray_tun_config(server: &VpnServer, tunnel: &TunnelSettings) -> Result<Value, String> {
    let mut cfg = crate::vpn_manager::build_xray_config(server, tunnel)?;

    let sniffing = json!({ "enabled": true, "destOverride": ["http", "tls", "quic"] });

    cfg["inbounds"].as_array_mut().ok_or("в конфиге xray нет inbounds")?.push(json!({
        "tag": "tun-in",
        "port": 0,
        "protocol": "tun",
        "settings": {
            "name": TUN_NAME,
            "MTU": TUN_MTU,
            "gateway": [TUN_ADDR],
            "autoSystemRoutingTable": ["0.0.0.0/0"],
            "autoOutboundsInterface": "auto"
        },
        "sniffing": sniffing
    }));

    cfg["outbounds"]
        .as_array_mut()
        .ok_or("в конфиге xray нет outbounds")?
        .push(json!({ "protocol": "dns", "tag": "dns-out" }));

    // После правила Stats API (индекс 0): DNS из TUN -> встроенный DNS xray, затем LAN -> direct.
    let rules = cfg["routing"]["rules"].as_array_mut().ok_or("в конфиге xray нет rules")?;
    rules.insert(1, json!({ "type": "field", "inboundTag": ["tun-in"], "port": 53, "outboundTag": "dns-out" }));
    rules.insert(2, json!({
        "type": "field",
        "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"],
        "outboundTag": "direct"
    }));

    Ok(cfg)
}

// ---------------------------------------------------------------------------------------
// Установка ядер и wintun
// ---------------------------------------------------------------------------------------

pub fn core_dir(resources_dir: &Path, name: &str) -> PathBuf {
    resources_dir.join(name)
}

fn shared_wintun(resources_dir: &Path) -> PathBuf {
    resources_dir.join("wintun").join("wintun.dll")
}

/// Если очередной скачанный архив принёс свой wintun.dll — запоминаем его как общий.
fn absorb_wintun(resources_dir: &Path, dir: &Path) {
    let shared = shared_wintun(resources_dir);
    let local = dir.join("wintun.dll");
    if !shared.exists() && local.exists() {
        if let Some(parent) = shared.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(&local, &shared);
    }
}

async fn ensure_wintun(resources_dir: &Path, report: &(dyn Fn(&str) + Send + Sync)) -> Result<(), String> {
    let shared = shared_wintun(resources_dir);
    if shared.exists() {
        return Ok(());
    }
    report("скачиваю wintun.dll…");
    crate::updater::install_wintun(&resources_dir.join("wintun"))
        .await
        .map_err(|e| {
            format!(
                "не удалось скачать wintun.dll ({e}). Положите wintun.dll (amd64) вручную сюда: {}",
                shared.display()
            )
        })
}

async fn ensure_singbox(resources_dir: &Path, report: &(dyn Fn(&str) + Send + Sync)) -> Result<(), String> {
    let dir = core_dir(resources_dir, "singbox");
    if dir.join("sing-box.exe").exists() {
        return Ok(());
    }
    report("скачиваю sing-box…");
    crate::updater::install_release_zip(
        "SagerNet/sing-box",
        &[&["windows", "amd64"]],
        &["legacy", "arm"],
        "sing-box.exe",
        &dir,
    )
    .await
    .map_err(|e| format!("sing-box: {e}"))?;
    absorb_wintun(resources_dir, &dir);
    Ok(())
}

async fn ensure_tun2proxy(resources_dir: &Path, report: &(dyn Fn(&str) + Send + Sync)) -> Result<(), String> {
    let dir = core_dir(resources_dir, "tun2proxy");
    if dir.join("tun2proxy-bin.exe").exists() {
        return Ok(());
    }
    report("скачиваю tun2proxy…");
    crate::updater::install_release_zip(
        "tun2proxy/tun2proxy",
        &[&["windows", "x86_64"], &["windows", "amd64"], &["win", "64"]],
        &["aarch64", "arm", "i686"],
        "tun2proxy-bin.exe",
        &dir,
    )
    .await
    .map_err(|e| format!("tun2proxy: {e}"))?;
    absorb_wintun(resources_dir, &dir);
    Ok(())
}

/// Докачивает всё, что нужно выбранному режиму (при первом использовании). `report` —
/// человекочитаемый прогресс для интерфейса.
pub async fn ensure_cores(
    resources_dir: &Path,
    mode: VpnMode,
    report: &(dyn Fn(&str) + Send + Sync),
) -> Result<(), String> {
    let xray = core_dir(resources_dir, "xray").join("xray.exe");

    match mode {
        VpnMode::Proxy => Ok(()),
        VpnMode::XrayTun => {
            if !xray.exists() {
                return Err("xray.exe не найден — дождитесь первичной загрузки компонентов".into());
            }
            ensure_wintun(resources_dir, report).await
        }
        VpnMode::SingBox | VpnMode::Adaptive => {
            ensure_singbox(resources_dir, report).await?;
            ensure_wintun(resources_dir, report).await
        }
        VpnMode::Tun2Proxy => {
            if !xray.exists() {
                return Err("xray.exe не найден — дождитесь первичной загрузки компонентов".into());
            }
            ensure_tun2proxy(resources_dir, report).await?;
            ensure_wintun(resources_dir, report).await
        }
    }
}

/// Кладёт общий wintun.dll рядом с exe ядра (Windows ищет dll в папке запускаемого exe).
/// Вызывается прямо перед запуском: обновление ядра (replace_dir) стирает папку целиком,
/// поэтому единственная "правда" лежит в resources/wintun, а не в папке ядра.
pub fn place_wintun(resources_dir: &Path, dir: &Path) -> Result<(), String> {
    let shared = shared_wintun(resources_dir);
    if !shared.exists() {
        return Err(format!("не найден wintun.dll ({})", shared.display()));
    }
    let target = dir.join("wintun.dll");
    let same = std::fs::metadata(&target)
        .and_then(|a| std::fs::metadata(&shared).map(|b| a.len() == b.len()))
        .unwrap_or(false);
    if !same {
        std::fs::copy(&shared, &target).map_err(|e| format!("не удалось скопировать wintun.dll: {e}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Сеть Windows
// ---------------------------------------------------------------------------------------

/// Индекс физического интерфейса с маршрутом по умолчанию — к нему привязывается winws
/// (--wf-iface), чтобы не перехватывать и не портить трафик внутри TUN-адаптера.
/// Вызывать ДО подъёма TUN, иначе маршрут по умолчанию уже будет указывать на него.
#[cfg(windows)]
pub fn detect_physical_ifindex() -> Option<u32> {
    use std::os::windows::process::CommandExt;
    let script = format!(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne '{TUN_NAME}' }} | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x08000000)
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(not(windows))]
pub fn detect_physical_ifindex() -> Option<u32> {
    None
}

/// IPv4-адреса сервера — для --bypass у tun2proxy (трафик самого прокси до сервера
/// не должен заворачиваться обратно в TUN).
pub fn resolve_server_ips(host: &str, port: u16) -> Vec<String> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .map(|it| it.filter(|a| a.is_ipv4()).map(|a| a.ip().to_string()).collect::<Vec<_>>())
        .unwrap_or_default()
}
