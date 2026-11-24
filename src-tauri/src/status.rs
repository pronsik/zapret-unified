use serde::Serialize;
use std::time::Duration;

#[derive(Serialize, Clone)]
pub struct ServiceStatus {
    pub name: String,
    pub ok: bool,
    pub latency_ms: Option<u128>,
    pub error: Option<String>,
}

/// Простая проверка: удаётся ли за разумное время получить HTTP-ответ с сайта,
/// который обычно душится DPI без обхода. Это не гарантирует "видео точно грузится",
/// но отличает "заблокировано/тротлится" от "соединение проходит".
async fn check(name: &str, url: &str) -> ServiceStatus {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ServiceStatus {
                name: name.into(),
                ok: false,
                latency_ms: None,
                error: Some(e.to_string()),
            }
        }
    };

    let start = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(resp) => ServiceStatus {
            name: name.into(),
            ok: resp.status().is_success() || resp.status().is_redirection(),
            latency_ms: Some(start.elapsed().as_millis()),
            error: None,
        },
        Err(e) => ServiceStatus {
            name: name.into(),
            ok: false,
            latency_ms: None,
            error: Some(e.to_string()),
        },
    }
}

pub async fn check_all() -> Vec<ServiceStatus> {
    // Порядок проверок соответствует тому, что покрывает zapret из коробки.
    let checks = vec![
        check("YouTube", "https://www.youtube.com/generate_204"),
        check("Discord", "https://discord.com/api/v9/gateway"),
        check("Telegram", "https://web.telegram.org/"),
    ];
    futures_join_all(checks).await
}

// Небольшая замена futures::future::join_all, чтобы не тянуть весь crate `futures`
// ради одной функции — tokio::join! не годится для Vec произвольной длины.
async fn futures_join_all(
    tasks: Vec<impl std::future::Future<Output = ServiceStatus>>,
) -> Vec<ServiceStatus> {
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        out.push(t.await);
    }
    out
}
