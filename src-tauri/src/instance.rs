//! Защита от второго экземпляра. Без внешних зависимостей: первый экземпляр занимает
//! локальный TCP-порт; второй, не сумев его занять, просит первого показать окно и выходит.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

const ADDR: &str = "127.0.0.1:47831";
const HELLO: &[u8] = b"show";
// Ответ нужен, чтобы отличить наш экземпляр от постороннего приложения, случайно занявшего порт:
// в этом случае мы НЕ выходим, а просто запускаемся без защиты.
const REPLY: &[u8] = b"zapret-unified-ok";

pub enum Guard {
    /// Мы первые: держим порт и обслуживаем запросы "покажи окно".
    Primary(TcpListener),
    /// Наш экземпляр уже запущен и получил просьбу показать окно — нужно выйти.
    Secondary,
    /// Порт занят чужой программой — работаем без защиты от дублей.
    Unavailable,
}

pub fn acquire() -> Guard {
    match TcpListener::bind(ADDR) {
        Ok(l) => Guard::Primary(l),
        Err(_) => {
            if let Ok(addr) = ADDR.parse::<SocketAddr>() {
                if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                    let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
                    let _ = s.write_all(HELLO);
                    let mut buf = [0u8; 32];
                    if let Ok(n) = s.read(&mut buf) {
                        if &buf[..n] == REPLY {
                            return Guard::Secondary;
                        }
                    }
                }
            }
            Guard::Unavailable
        }
    }
}

/// Обслуживает запросы второго экземпляра в отдельном потоке.
pub fn serve(listener: TcpListener, on_show: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = [0u8; 8];
            if let Ok(n) = stream.read(&mut buf) {
                if &buf[..n] == HELLO {
                    let _ = stream.write_all(REPLY);
                    on_show();
                }
            }
        }
    });
}
