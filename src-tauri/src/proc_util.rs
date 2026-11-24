use std::path::PathBuf;
use std::process::Child;
use std::time::{Duration, Instant};

/// Убирает префикс `\\?\` (verbatim-путь) из пути. Tauri отдаёт resource_dir именно в такой
/// форме, а консольные программы на cygwin (winws.exe) и многие другие инструменты не
/// умеют открывать файлы по таким путям: "could not read \\?\C:\...\quic_initial.bin".
pub fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy().to_string();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        // только дисковые пути вида X:\..., прочие (\\?\Volume{...}) не трогаем
        if rest.as_bytes().get(1) == Some(&b':') {
            return PathBuf::from(rest.to_string());
        }
    }
    p
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(process_id: u32) -> i32;
    fn FreeConsole() -> i32;
    fn GenerateConsoleCtrlEvent(ctrl_event: u32, process_group_id: u32) -> i32;
    fn SetConsoleCtrlHandler(handler: *const core::ffi::c_void, add: i32) -> i32;
    fn SetStdHandle(std_handle: u32, handle: *mut core::ffi::c_void) -> i32;
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *mut core::ffi::c_void;
    fn WaitForSingleObject(handle: *mut core::ffi::c_void, milliseconds: u32) -> u32;
    fn TerminateProcess(handle: *mut core::ffi::c_void, exit_code: u32) -> i32;
    fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
}

#[cfg(windows)]
const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
#[cfg(windows)]
const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
#[cfg(windows)]
const STD_ERROR_HANDLE: u32 = (-12i32) as u32;

/// Останавливает дочерний процесс "по-хорошему": посылает ему Ctrl+C и ждёт до `wait`,
/// и только потом убивает принудительно.
///
/// Для TUN-режимов это не прихоть, а необходимость. Если просто убить sing-box/xray/
/// tun2proxy через TerminateProcess, они не успевают удалить TUN-адаптер и свои
/// маршруты — default route остаётся указывать в мёртвый интерфейс, и у пользователя
/// пропадает интернет целиком до следующего запуска. По Ctrl+C все три ядра
/// штатно закрывают адаптер и откатывают маршруты.
///
/// Процессы запускаются с CREATE_NO_WINDOW — у них есть скрытая консоль, к которой
/// можно подключиться через AttachConsole и отправить событие. Само приложение —
/// GUI без консоли, поэтому подключение к чужой консоли не конфликтует с нашей.
#[cfg(windows)]
pub fn graceful_stop(child: &mut Child, wait: Duration) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }

    unsafe {
        FreeConsole();
        if AttachConsole(child.id()) != 0 {
            // Пока мы подключены к консоли ребёнка, Ctrl+C прилетит и нам — игнорируем.
            SetConsoleCtrlHandler(core::ptr::null(), 1);
            GenerateConsoleCtrlEvent(0, 0); // CTRL_C_EVENT

            let started = Instant::now();
            while started.elapsed() < wait {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            FreeConsole();
            SetConsoleCtrlHandler(core::ptr::null(), 0);

            // КРИТИЧНО. AttachConsole проставляет процессу стандартные дескрипторы
            // (stdin/stdout/stderr) консоли ребёнка, а FreeConsole их закрывает — но сами
            // значения в процессе остаются. Следующий Command::spawn с унаследованным stdin
            // пытается их продублировать и падает с "Неверный дескриптор (os error 6)".
            // Поэтому первое подключение работало, а любое следующее — нет.
            SetStdHandle(STD_INPUT_HANDLE, core::ptr::null_mut());
            SetStdHandle(STD_OUTPUT_HANDLE, core::ptr::null_mut());
            SetStdHandle(STD_ERROR_HANDLE, core::ptr::null_mut());
        }
    }

    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(not(windows))]
pub fn graceful_stop(child: &mut Child, _wait: Duration) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Завершает процесс по PID — для "осиротевших" процессов, у которых у нас нет `Child`
/// (остались от прошлого сеанса, от сбоя или от гонки подключений). Если задан `graceful`,
/// сначала шлёт Ctrl+C и ждёт столько времени (TUN-ядра так откатывают адаптер и маршруты),
/// затем завершает жёстко. Возвращает true, если процесса больше нет.
#[cfg(windows)]
pub fn stop_pid(pid: u32, graceful: Option<Duration>) -> bool {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const WAIT_OBJECT_0: u32 = 0;

    unsafe {
        let handle = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return true; // процесса уже нет
        }

        if let Some(wait) = graceful {
            FreeConsole();
            if AttachConsole(pid) != 0 {
                SetConsoleCtrlHandler(core::ptr::null(), 1);
                GenerateConsoleCtrlEvent(0, 0);
                let ms = wait.as_millis().min(u32::MAX as u128) as u32;
                let r = WaitForSingleObject(handle, ms);
                FreeConsole();
                SetConsoleCtrlHandler(core::ptr::null(), 0);
                // см. комментарий в graceful_stop: после Attach/FreeConsole в процессе остаются
                // мёртвые стандартные дескрипторы, ломающие следующий Command::spawn.
                SetStdHandle(STD_INPUT_HANDLE, core::ptr::null_mut());
                SetStdHandle(STD_OUTPUT_HANDLE, core::ptr::null_mut());
                SetStdHandle(STD_ERROR_HANDLE, core::ptr::null_mut());
                if r == WAIT_OBJECT_0 {
                    CloseHandle(handle);
                    return true;
                }
            }
        }

        TerminateProcess(handle, 1);
        let r = WaitForSingleObject(handle, 3000);
        CloseHandle(handle);
        r == WAIT_OBJECT_0
    }
}

#[cfg(not(windows))]
pub fn stop_pid(_pid: u32, _graceful: Option<Duration>) -> bool {
    true
}
