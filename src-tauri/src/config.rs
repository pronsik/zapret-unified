use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

fn default_true() -> bool {
    true
}

fn default_vpn_mode() -> String {
    "proxy".to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VpnServer {
    pub id: String,
    pub name: String,
    pub protocol: String, // vless | vmess | trojan | shadowsocks
    /// Ссылка vless://… (формат LINK) либо JSON outbound xray (формат JSON).
    pub raw_link: String,
    /// Подписка, из которой пришёл сервер; None — добавлен вручную.
    #[serde(default)]
    pub sub_id: Option<String>,
    /// Транспорт для тега в интерфейсе: TCP / WS / GRPC / …
    #[serde(default)]
    pub transport: String,
    /// Защита канала: REALITY / TLS; пустая строка — без шифрования транспорта.
    #[serde(default)]
    pub security: String,
    /// Формат исходной записи: LINK или JSON.
    #[serde(default)]
    pub format: String,
}

/// Профиль маршрутизации: сохранённый набор правил и адресов в обход. Применяется целиком
/// (заменяет текущие правила туннеля).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RoutingProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub routing_rules: Vec<RoutingRule>,
    #[serde(default)]
    pub bypass_addresses: Vec<BypassAddress>,
}

/// Встроенные профили: есть всегда, их не нужно сохранять вручную. Правила "direct" — сайты,
/// которые идут напрямую, мимо VPN. Список доменов можно расширять в этом месте.
pub fn builtin_profiles() -> Vec<RoutingProfile> {
    fn profile(id: &str, name: &str, domains: &[&str]) -> RoutingProfile {
        RoutingProfile {
            id: id.to_string(),
            name: name.to_string(),
            routing_rules: domains
                .iter()
                .enumerate()
                .map(|(i, d)| RoutingRule {
                    id: format!("{id}-rule-{i}"),
                    value: format!("domain:{d}"),
                    action: "direct".to_string(),
                })
                .collect(),
            bypass_addresses: Vec::new(),
        }
    }
    vec![
        profile("builtin-all", "Всё через VPN", &[]),
        profile(
            "builtin-ru",
            "Россия: отечественные сайты напрямую",
            &["ru", "su", "xn--p1ai", "vk.com", "vk.me", "yandex.net", "yastatic.net", "userapi.com", "mycdn.me"],
        ),
        profile(
            "builtin-cn",
            "Китай: китайские сайты напрямую",
            &["cn", "xn--fiqs8s", "baidu.com", "qq.com", "taobao.com", "tmall.com", "jd.com", "bilibili.com", "alipay.com", "163.com"],
        ),
    ]
}

/// Настройки tg-ws-proxy-rs. Каждое поле соответствует флагу командной строки (см. README
/// проекта); приложение собирает из них аргументы при запуске (`tgproxy_manager::build_args`).
///
/// По умолчанию сам tg-ws-proxy-rs привязывается к 0.0.0.0, если находит адрес в локальной
/// сети (то есть открывает прокси всем устройствам сети), и при каждом запуске генерирует новый
/// секрет — из-за чего ссылка tg://proxy менялась бы при каждом включении. Поэтому здесь по
/// умолчанию 127.0.0.1 и постоянный секрет.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct TgProxySettings {
    pub port: u16,
    /// false — слушать только этот компьютер (127.0.0.1); true — всю локальную сеть (0.0.0.0).
    pub lan_access: bool,
    /// 32 hex-символа; пустая строка — будет сгенерирован при первом запуске и сохранён.
    pub secret: String,
    /// Предпрогретых WebSocket-соединений на каждый DC; 0 — значение по умолчанию (4).
    pub pool_size: u32,
    pub default_domains: bool,
    pub cf_domain: String,
    pub cf_worker_domain: String,
    pub cf_balance: bool,
    pub cf_disable_tls: bool,
    /// Порядок способов подключения: ws,cfworker,cfproxy,mtproto,tcp; пусто — по умолчанию.
    pub pinned_upstream: String,
    pub fronting_domain: String,
    /// Строки вида `2:149.154.167.220` (DC:IP).
    pub dc_ips: Vec<String>,
    /// Строки вида `host:port:secret`.
    pub mtproto_proxies: Vec<String>,
    pub outbound_proxy: String,
    pub verbose: bool,
    /// Любые дополнительные флаги одной строкой (с учётом кавычек).
    pub extra_args: String,
}

impl Default for TgProxySettings {
    fn default() -> Self {
        Self {
            port: 1443,
            lan_access: false,
            secret: String::new(),
            pool_size: 1,
            default_domains: false,
            cf_domain: String::new(),
            cf_worker_domain: String::new(),
            cf_balance: false,
            cf_disable_tls: false,
            pinned_upstream: "ws,cfworker,cfproxy,mtproto,tcp".to_string(),
            fronting_domain: String::new(),
            dc_ips: vec!["2:149.154.167.220".to_string(), "4:149.154.167.220".to_string()],
            mtproto_proxies: Vec::new(),
            outbound_proxy: String::new(),
            verbose: false,
            extra_args: String::new(),
        }
    }
}

/// Подписка: URL, который отдаёт список серверов, плюс метаданные из стандартных заголовков
/// ответа (`subscription-userinfo`, `profile-update-interval`, `support-url` и т.д.) —
/// их показывает карточка подписки (трафик, срок, интервал, поддержка).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// Свой User-Agent: некоторые панели выбирают формат ответа (ссылки или JSON) по нему.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Раз в сколько часов обновлять автоматически; 0 — не обновлять.
    #[serde(default)]
    pub interval_hours: u32,
    /// Unix-время последнего успешного обновления; 0 — никогда.
    #[serde(default)]
    pub last_updated: i64,
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    /// Лимит трафика в байтах; 0 — безлимит.
    #[serde(default)]
    pub total: u64,
    /// Unix-время окончания подписки; 0 — бессрочная.
    #[serde(default)]
    pub expire: i64,
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub web_page_url: Option<String>,
    #[serde(default)]
    pub announce: Option<String>,
}

/// Фрагментация TLS ClientHello — штатная фича xray-core (outbound "freedom" с полем
/// "fragment"), помогает против DPI, которая режет по первому пакету с SNI.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FragmentSettings {
    pub enabled: bool,
    /// Что фрагментировать: "tlshello" (только TLS ClientHello) — самый частый вариант,
    /// либо диапазон номеров пакетов вида "1-3" (синтаксис xray-core как есть).
    pub packets: String,
    /// Размер фрагмента в байтах, диапазон вида "10-30".
    pub length: String,
    /// Пауза между фрагментами в мс, диапазон вида "10-30".
    pub interval: String,
}

impl Default for FragmentSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            packets: "tlshello".into(),
            length: "10-30".into(),
            interval: "10-30".into(),
        }
    }
}

/// Мультиплексирование нескольких логических соединений в одно — xray-core "mux".
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MuxSettings {
    pub enabled: bool,
    pub concurrency: u32,
}

impl Default for MuxSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            concurrency: 8,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DnsSettings {
    /// "cloudflare_google" (по умолчанию, 1.1.1.1+8.8.8.8) | "google" | "cloudflare" | "quad9" | "custom".
    pub mode: String,
    /// Используется только при mode == "custom". Обычные IP ("1.1.1.1") или DoH ("https://dns.google/dns-query").
    pub servers: Vec<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            mode: "cloudflare_google".into(),
            servers: Vec::new(),
        }
    }
}

/// Адрес/паттерн для раздела "Адреса в обход прокси" — независим от per-app: применяется
/// всегда, вне зависимости от того, какое приложение шлёт трафик. Принимает то, что удобно
/// пользователю (полный IP/CIDR, "*.ru", "yandex.ru", "yandex.ru/*") — нормализуется в
/// xray-синтаксис в vpn_manager::build_xray_config.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BypassAddress {
    pub id: String,
    pub value: String,
}

/// Отправка HWID (аппаратного идентификатора устройства) вместе с запросом подписки —
/// нужно панелям вроде Marzban/Remnawave, которые привязывают ключ к устройству.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubscriptionSettings {
    pub send_hwid: bool,
    pub last_url: Option<String>,
}

impl Default for SubscriptionSettings {
    fn default() -> Self {
        Self {
            send_hwid: true,
            last_url: None,
        }
    }
}

/// Правило профиля маршрутизации. value — в синтаксисе xray-core как есть:
/// обычный домен ("youtube.com"), IP/CIDR, либо готовый набор "geosite:google" /
/// "geoip:ru" (используются встроенные в xray-core geo-файлы).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RoutingRule {
    pub id: String,
    pub value: String,
    pub action: String, // "proxy" | "direct" | "block"
}

/// Per-app proxy на десктопе без TUN-адаптера реализуем через флаги командной строки
/// Chromium-приложений (chrome/edge/brave/opera/vivaldi/discord — все на Electron/Chromium):
/// --proxy-server=... или --no-proxy-server. Поэтому apps должны быть из уже знакомого
/// whitelist-набора имён .exe. Firefox так не работает (нет такого CLI-флага) — не поддержан.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PerAppSettings {
    pub enabled: bool,
    /// "only" — через VPN идут только apps, остальное напрямую (системный прокси выключен).
    /// "bypass" — через VPN идёт всё (системный прокси включён), кроме apps.
    pub mode: String,
    pub apps: Vec<String>,
}

impl Default for PerAppSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "only".into(),
            apps: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunnelSettings {
    pub fragment: FragmentSettings,
    pub mux: MuxSettings,
    pub dns: DnsSettings,
    pub routing_rules: Vec<RoutingRule>,
    pub per_app: PerAppSettings,
    /// Определение протокола на inbound (http/tls/quic) для более точной маршрутизации.
    pub sniffing_enabled: bool,
    pub bypass_addresses: Vec<BypassAddress>,
    pub subscription: SubscriptionSettings,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    /// Имена .exe, которым разрешено работать через обход DPI.
    pub whitelist: Vec<String>,
    /// Выбранная стратегия winws.exe (см. strategies.json рядом с ресурсами zapret).
    pub strategy: String,
    /// Включён ли tg-ws-proxy.
    pub tgproxy_enabled: bool,
    /// Мастер-переключатель обхода DPI. Когда false — watch_loop не трогает winws.exe,
    /// даже если среди процессов есть whitelisted-приложения.
    #[serde(default = "default_true")]
    pub zapret_enabled: bool,
    /// Режим работы VPN: "proxy" (xray SOCKS/HTTP + системный прокси), "xray-tun",
    /// "singbox" (TUN на ядре sing-box), "tun2proxy" (xray + tun2proxy) или
    /// "adaptive" (собственный адаптивный split-TUN поверх sing-box).
    #[serde(default = "default_vpn_mode")]
    pub vpn_mode: String,
    /// Проверять обновления zapret/tg-ws-proxy автоматически в фоне.
    pub auto_update: bool,
    /// tag_name последнего установленного релиза Flowseal/zapret-discord-youtube.
    pub zapret_version: Option<String>,
    /// tag_name последнего установленного релиза Flowseal/tg-ws-proxy.
    pub tgproxy_version: Option<String>,
    /// tag_name последнего установленного релиза XTLS/Xray-core.
    pub xray_version: Option<String>,
    /// Когда последний раз реально ходили на GitHub проверять версии (RFC3339).
    pub last_checked: Option<String>,
    /// Сохранённые VPN-серверы (добавленные по ссылке vless/vmess/trojan/ss).
    pub vpn_servers: Vec<VpnServer>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub tgproxy_settings: TgProxySettings,
    #[serde(default)]
    pub profiles: Vec<RoutingProfile>,
    /// id сервера, который сейчас активен (или должен быть активен после перезапуска).
    pub vpn_active_id: Option<String>,
    /// Прописывать ли локальный прокси xray-core как системный прокси Windows.
    pub vpn_system_proxy: bool,
    /// Настройки туннеля: фрагментация, mux, DNS, маршрутизация, per-app.
    pub tunnel: TunnelSettings,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            whitelist: vec![
                "chrome.exe",
                "msedge.exe",
                "firefox.exe",
                "brave.exe",
                "opera.exe",
                "vivaldi.exe",
                "Discord.exe",
                "DiscordCanary.exe",
                "DiscordPTB.exe",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            strategy: "general.bat".to_string(),
            tgproxy_enabled: false,
            zapret_enabled: true,
            vpn_mode: default_vpn_mode(),
            auto_update: true,
            zapret_version: None,
            tgproxy_version: None,
            xray_version: None,
            last_checked: None,
            vpn_servers: Vec::new(),
            subscriptions: Vec::new(),
            tgproxy_settings: TgProxySettings::default(),
            profiles: Vec::new(),
            vpn_active_id: None,
            vpn_system_proxy: false,
            tunnel: TunnelSettings::default(),
        }
    }
}

fn config_path() -> PathBuf {
    let mut dir = tauri::api::path::app_config_dir(&tauri::Config::default())
        .unwrap_or_else(std::env::temp_dir);
    let _ = fs::create_dir_all(&dir);
    dir.push("config.json");
    dir
}

pub fn load() -> AppConfig {
    let path = config_path();
    match fs::read_to_string(&path) {
        Ok(s) => match serde_json::from_str(&s) {
            Ok(cfg) => cfg,
            Err(_) => {
                // Раньше при любой ошибке разбора молча возвращался конфиг по умолчанию и
                // следующее сохранение стирало все серверы. Теперь повреждённый файл
                // сначала откладывается рядом, чтобы его можно было восстановить вручную.
                let _ = fs::copy(&path, path.with_extension("json.bad"));
                AppConfig::default()
            }
        },
        Err(_) => AppConfig::default(),
    }
}

pub fn save(cfg: &AppConfig) -> anyhow::Result<()> {
    let path = config_path();
    let s = serde_json::to_string_pretty(cfg)?;
    // Запись через временный файл + переименование: обрыв посреди записи (закрыли окно,
    // выключили питание) не оставит наполовину записанный config.json.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, s)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn add_app(cfg: &mut AppConfig, exe_name: String) -> anyhow::Result<()> {
    if !cfg.whitelist.iter().any(|e| e.eq_ignore_ascii_case(&exe_name)) {
        cfg.whitelist.push(exe_name);
        save(cfg)?;
    }
    Ok(())
}

pub fn remove_app(cfg: &mut AppConfig, exe_name: &str) -> anyhow::Result<()> {
    cfg.whitelist.retain(|e| !e.eq_ignore_ascii_case(exe_name));
    save(cfg)
}

pub fn add_vpn_server(cfg: &mut AppConfig, server: VpnServer) -> anyhow::Result<()> {
    cfg.vpn_servers.push(server);
    save(cfg)
}

pub fn remove_vpn_server(cfg: &mut AppConfig, id: &str) -> anyhow::Result<()> {
    cfg.vpn_servers.retain(|s| s.id != id);
    if cfg.vpn_active_id.as_deref() == Some(id) {
        cfg.vpn_active_id = None;
    }
    save(cfg)
}

pub fn add_routing_rule(cfg: &mut AppConfig, rule: RoutingRule) -> anyhow::Result<()> {
    cfg.tunnel.routing_rules.push(rule);
    save(cfg)
}

pub fn remove_routing_rule(cfg: &mut AppConfig, id: &str) -> anyhow::Result<()> {
    cfg.tunnel.routing_rules.retain(|r| r.id != id);
    save(cfg)
}

pub fn add_bypass_address(cfg: &mut AppConfig, value: String) -> anyhow::Result<()> {
    let id = format!(
        "bypass-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    cfg.tunnel.bypass_addresses.push(BypassAddress { id, value });
    save(cfg)
}

pub fn remove_bypass_address(cfg: &mut AppConfig, id: &str) -> anyhow::Result<()> {
    cfg.tunnel.bypass_addresses.retain(|b| b.id != id);
    save(cfg)
}
