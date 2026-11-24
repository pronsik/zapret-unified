use crate::process_monitor::resolve_pids;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// winws.exe — консольная программа. Без этого флага Windows всё равно открывает ей
/// окно консоли, даже когда stdout/stderr уже уведены в пайп на нашу сторону — получается
/// пустое висящее окно. CREATE_NO_WINDOW запрещает создавать окно консоли вообще.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
/// winws.exe гоняет через себя пакеты в пользовательском режиме — при нехватке процессора
/// под нагрузкой это превращается в рост задержки у всей сети, поэтому приоритет чуть выше.
#[cfg(windows)]
const ABOVE_NORMAL_PRIORITY_CLASS: u32 = 0x0000_8000;

const MAX_LOG_LINES: usize = 400;

/// Тестовые цели для проверки стратегии — те же сервисы, ради которых вообще существует
/// этот репозиторий (Discord, YouTube) плюс пара универсальных "точно заблокированных
/// при плохой стратегии" адресов.
const TEST_TARGETS: &[(&str, &str)] = &[
    ("discord.com", "https://discord.com"),
    ("youtube.com", "https://www.youtube.com/generate_204"),
    ("discord gateway (voice/api)", "https://gateway.discord.gg"),
];

/// Что сейчас происходит с обходом — для интерфейса. `state`: init | paused | disabled |
/// waiting | no_args | starting | running | exited | error; `detail` — человекочитаемая причина.
#[derive(serde::Serialize, Clone)]
pub struct ZapretStatus {
    pub running: bool,
    pub state: String,
    pub detail: String,
    pub pid: Option<u32>,
}

#[derive(serde::Serialize, Clone)]
pub struct TestTarget {
    pub name: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(serde::Serialize, Clone)]
pub struct StrategyTestResult {
    pub strategy: String,
    pub targets: Vec<TestTarget>,
}

pub struct ZapretManager {
    child: Mutex<Option<Child>>,
    last_pids: Mutex<HashSet<u32>>,
    resources_dir: PathBuf,
    logs: std::sync::Arc<Mutex<std::collections::VecDeque<String>>>,
    /// Пока true, watch_loop::tick() ничего не делает и не трогает winws.exe/файлы.
    /// Выставляется апдейтером на время замены bin/lists, чтобы не словить
    /// "файл занят процессом" и не запустить winws.exe поверх недописанных файлов.
    paused: AtomicBool,
    /// Мастер-переключатель, управляемый пользователем из UI (кнопка вкл/выкл на
    /// странице zapret). В отличие от `paused` — сохраняется между запусками
    /// приложения через AppConfig.zapret_enabled.
    user_enabled: AtomicBool,
    /// Аргументы, с которыми winws.exe запущен сейчас — чтобы перезапускать его только
    /// при реальном изменении стратегии/привязки к интерфейсу, а не на каждом тике.
    last_args: Mutex<Vec<String>>,
    /// Индекс физического сетевого интерфейса, к которому привязывается перехват
    /// (--wf-iface). Нужен, когда поднят TUN-адаптер: без привязки winws перехватывает и
    /// внутренний трафик самого TUN и портит его fake-пакетами.
    iface_pin: Mutex<Option<u32>>,
    /// Момент последней попытки запуска — защита от бесконечного перезапуска, если
    /// winws.exe сразу падает (например, невалидный аргумент).
    last_spawn: Mutex<Option<std::time::Instant>>,
    /// (state, detail) — последнее решение наблюдателя, показывается в интерфейсе.
    state: Mutex<(String, String)>,
    /// Ошибка разбора выбранной стратегии (.bat) — единственная причина, по которой
    /// наблюдатель получает пустой список аргументов.
    args_error: Mutex<Option<String>>,
    /// Сериализует выгрузку драйвера WinDivert и запуск winws.exe: иначе новый запуск мог бы
    /// попасть на "службу, помеченную на удаление" и упасть.
    driver_lock: Mutex<()>,
    /// Идёт тест стратегии: наблюдатель не трогает winws.exe, пока тест не закончен.
    testing: AtomicBool,
}

impl ZapretManager {
    pub fn new(resources_dir: PathBuf) -> Self {
        Self {
            child: Mutex::new(None),
            last_pids: Mutex::new(HashSet::new()),
            resources_dir,
            paused: AtomicBool::new(false),
            user_enabled: AtomicBool::new(true),
            last_args: Mutex::new(Vec::new()),
            iface_pin: Mutex::new(None),
            last_spawn: Mutex::new(None),
            state: Mutex::new(("init".to_string(), "запуск…".to_string())),
            args_error: Mutex::new(None),
            driver_lock: Mutex::new(()),
            testing: AtomicBool::new(false),
            logs: std::sync::Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(MAX_LOG_LINES))),
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

    /// Включает/выключает обход вручную. При выключении сразу останавливает
    /// winws.exe, если он был запущен; при включении просто снимает блокировку —
    /// реальный запуск произойдёт на следующем тике watch_loop, если появится
    /// whitelisted-процесс.
    pub fn set_user_enabled(&self, enabled: bool) {
        self.user_enabled.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.stop_locked();
            self.last_pids.lock().unwrap().clear();
            self.last_args.lock().unwrap().clear();
            self.release_driver();
        }
    }

    #[allow(dead_code)]
    pub fn is_user_enabled(&self) -> bool {
        self.user_enabled.load(Ordering::SeqCst)
    }

    /// Привязка перехвата winws.exe к одному сетевому интерфейсу (None — снять привязку).
    /// Следующий тик watch_loop сам перезапустит winws.exe с новым --wf-iface.
    pub fn set_iface_pin(&self, idx: Option<u32>) {
        *self.iface_pin.lock().unwrap() = idx;
    }

    pub fn push_external_log(&self, line: String) {
        Self::push_log(&self.logs, line);
    }

    pub fn set_args_error(&self, e: Option<String>) {
        *self.args_error.lock().unwrap() = e;
    }

    fn set_state(&self, state: &str, detail: impl Into<String>) {
        *self.state.lock().unwrap() = (state.to_string(), detail.into());
    }

    fn log_tail(&self, n: usize) -> String {
        let l = self.logs.lock().unwrap();
        l.iter()
            .rev()
            .take(n)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ")
    }

    pub fn status(&self) -> ZapretStatus {
        let (state, detail) = self.state.lock().unwrap().clone();
        let (running, pid) = {
            let mut g = self.child.lock().unwrap();
            match g.as_mut() {
                Some(c) => (matches!(c.try_wait(), Ok(None)), Some(c.id())),
                None => (false, None),
            }
        };
        ZapretStatus {
            running,
            state,
            detail,
            pid: if running { pid } else { None },
        }
    }

    /// Проверка одной стратегии: запускает winws.exe с её аргументами (системный перехват
    /// по портам из самого .bat — так же, как при ручном запуске general.bat) и делает
    /// HTTP-запросы к тестовым доменам из этого же процесса. По смыслу аналог
    /// Run Test из service.bat оригинального репозитория, но без PowerShell/curl.
    /// `on_event(idx, None)` — цель начала проверяться; `on_event(idx, Some(ok))` — проверена.
    pub async fn test_strategy(&self, strategy_args: &[String], on_event: &(dyn Fn(usize, Option<bool>) + Sync)) -> Vec<TestTarget> {
        self.testing.store(true, Ordering::SeqCst);
        let result = self.test_strategy_inner(strategy_args, on_event).await;
        self.testing.store(false, Ordering::SeqCst);
        result
    }

    async fn test_strategy_inner(&self, strategy_args: &[String], on_event: &(dyn Fn(usize, Option<bool>) + Sync)) -> Vec<TestTarget> {
        self.stop_locked();
        self.last_pids.lock().unwrap().clear();
        self.last_args.lock().unwrap().clear();

        let child = match self.spawn(strategy_args) {
            Ok(c) => c,
            Err(e) => {
                return vec![TestTarget {
                    name: "winws.exe".into(),
                    ok: false,
                    error: Some(format!("не удалось запустить: {e}")),
                }]
            }
        };
        *self.child.lock().unwrap() = Some(child);

        // WinDivert-перехвату нужно время прикрепиться к сетевому стеку.
        tokio::time::sleep(Duration::from_millis(800)).await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
            .unwrap_or_default();

        let mut results = Vec::with_capacity(TEST_TARGETS.len());
        for (idx, &(name, url)) in TEST_TARGETS.iter().enumerate() {
            on_event(idx, None);
            let res = client.get(url).send().await;
            let (ok, error) = match res {
                Ok(r) => (r.status().is_success() || r.status().is_redirection(), None),
                Err(e) => (false, Some(e.to_string())),
            };
            on_event(idx, Some(ok));
            results.push(TestTarget { name: name.into(), ok, error });
        }

        self.stop_locked();
        self.release_driver();
        results
    }

    fn winws_path(&self) -> PathBuf {
        self.resources_dir.join("zapret").join("bin").join("winws.exe")
    }

    /// Запускает winws.exe с готовым списком аргументов из .bat стратегии (они уже содержат
    /// --wf-tcp/--wf-udp и все пути к hostlist/bin-файлам). Раньше сюда добавлялся ещё
    /// --wf-raw с условием "processId == N", но у слоя NETWORK в WinDivert нет поля
    /// processId (оно есть только у FLOW/SOCKET/REFLECT) — такой фильтр невалиден,
    /// WinDivertOpen падал с ошибкой 87, и обход не работал вообще.
    fn spawn(&self, args: &[String]) -> anyhow::Result<Child> {
        // Если в этот момент выгружается драйвер, дожидаемся: запуск на "службе, помеченной на
        // удаление", падает.
        drop(self.driver_lock.lock().unwrap());
        let exe = self.winws_path();
        let bin_dir = self.resources_dir.join("zapret").join("bin");

        let mut cmd = Command::new(exe);
        // stdin = null: см. комментарий в proc_util::graceful_stop — унаследованный stdin
        // после остановки VPN-ядра содержал бы мёртвый дескриптор (os error 6).
        cmd.current_dir(&bin_dir)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW | ABOVE_NORMAL_PRIORITY_CLASS);

        let mut child = cmd.spawn()?;

        // Без вычитывания пайпа в фоне winws.exe рано или поздно застопорится на
        // попытке что-то написать в stdout/stderr, как только заполнится буфер ОС
        // (~64 КБ) — раньше этот вывод никто не читал вообще.
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

        Ok(child)
    }

    fn stop_locked(&self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Раньше на этом всё и заканчивалось: потерянные winws.exe (прошлый сеанс, сбой) жили
        // дальше и держали драйвер WinDivert открытым.
        self.kill_stray_winws();
    }

    /// Завершает winws.exe из нашей папки, у которых нет дескриптора `Child`. Возвращает,
    /// сколько процессов завершено.
    fn kill_stray_winws(&self) -> usize {
        crate::process_monitor::sweep_many(
            &[("winws.exe", self.resources_dir.join("zapret").join("bin"))],
            None,
        )
    }

    /// Выгружает драйвер WinDivert. winws.exe открывает его как службу ядра, и после выхода
    /// процесса она остаётся загруженной — файлы WinDivert64.sys/WinDivert.dll остаются
    /// "заняты" (их нельзя заменить при обновлении или удалить), пока службу не остановят.
    /// Это тот самый шаг "Remove Services" из service.bat, который раньше приходилось делать руками.
    fn release_driver(&self) -> Vec<String> {
        let _guard = self.driver_lock.lock().unwrap();
        let mut report = Vec::new();
        for name in ["WinDivert", "WinDivert14"] {
            report.push(describe_sc(&format!("драйвер {name}: остановка"), sc(&["stop", name])));
            report.push(describe_sc(&format!("драйвер {name}: удаление"), sc(&["delete", name])));
        }
        report
    }

    /// Подметает потерянные winws.exe; если что-то нашлось — выгружает драйвер. Вызывается при
    /// старте приложения: после сбоя или принудительного закрытия прошлого сеанса.
    pub fn sweep_orphans(&self) -> usize {
        let n = self.kill_stray_winws();
        if n > 0 {
            self.release_driver();
        }
        n
    }

    /// Просит наблюдателя перезапустить winws.exe на ближайшем тике (например, после правки
    /// списков: winws читает hostlist-файлы только при старте).
    pub fn request_restart(&self) {
        self.last_args.lock().unwrap().clear();
    }

    /// Аналог "Remove Services" из service.bat: останавливает обход, завершает ВСЕ winws.exe в
    /// системе (taskkill /IM winws.exe /F), удаляет службу zapret (если её когда-то ставили через
    /// service.bat) и выгружает драйвер WinDivert. Обход остаётся выключенным, чтобы наблюдатель
    /// не поднял winws.exe обратно. Возвращает отчёт по шагам.
    pub fn remove_services(&self) -> Vec<String> {
        let mut report = Vec::new();

        self.user_enabled.store(false, Ordering::SeqCst);
        self.stop_locked();
        self.last_pids.lock().unwrap().clear();
        self.last_args.lock().unwrap().clear();
        report.push("обход выключен".to_string());

        report.push(describe_sc("служба zapret: остановка", sc(&["stop", "zapret"])));
        report.push(describe_sc("служба zapret: удаление", sc(&["delete", "zapret"])));

        let pids = crate::process_monitor::find_pids_by_name("winws.exe");
        if pids.is_empty() {
            report.push("winws.exe: запущенных процессов нет".to_string());
        }
        for pid in pids {
            let ok = crate::proc_util::stop_pid(pid, None);
            report.push(format!(
                "winws.exe (PID {pid}): {}",
                if ok { "завершён" } else { "не удалось завершить" }
            ));
        }

        report.extend(self.release_driver());
        report
    }

    pub fn stop(&self) {
        self.stop_locked();
        self.last_args.lock().unwrap().clear();
        self.last_pids.lock().unwrap().clear();
        self.release_driver();
    }

    /// Реально ли жив процесс winws.exe: раньше проверялось лишь "есть ли у нас Child",
    /// и интерфейс показывал "running" даже если winws.exe уже упал.
    pub fn is_running(&self) -> bool {
        let mut guard = self.child.lock().unwrap();
        match guard.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Останавливает winws.exe и запрещает watch_loop его перезапускать, пока не
    /// вызовут resume(). Используется апдейтером перед заменой файлов в resources/zapret.
    pub fn pause_for_update(&self) {
        self.paused.store(true, Ordering::SeqCst);
        self.stop_locked();
        // Обновление заменяет bin/ вместе с WinDivert64.sys — пока драйвер загружен, файл занят.
        self.release_driver();
        self.last_pids.lock().unwrap().clear();
    }

    pub fn resume_after_update(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    /// Один тик наблюдателя. Пустой whitelist = обход работает постоянно (как при ручном
    /// запуске general.bat); непустой — только пока запущено хотя бы одно из перечисленных
    /// приложений. Перезапуск — только если процесс умер или поменялись аргументы
    /// (стратегия / привязка к интерфейсу). Каждое решение записывается в `state`, чтобы
    /// интерфейс мог показать не просто "не работает", а почему.
    pub fn tick(&self, whitelist: &[String], strategy_args: &[String]) {
        // Во время теста стратегии winws.exe запущен вне наблюдателя. Раньше наблюдатель принимал
        // его за "не тот" процесс, останавливал и поднимал выбранную стратегию — отсюда ложные
        // состояния и "выключено" при тестах.
        if self.testing.load(Ordering::SeqCst) {
            return;
        }
        if self.paused.load(Ordering::SeqCst) {
            self.set_state("paused", "идёт обновление компонентов — обход временно остановлен");
            return;
        }
        if !self.user_enabled.load(Ordering::SeqCst) {
            self.set_state("disabled", "выключено вручную");
            return;
        }

        let pids = resolve_pids(whitelist);
        let want_running = whitelist.is_empty() || !pids.is_empty();

        if !want_running {
            if self.child.lock().unwrap().is_some() {
                self.stop_locked();
                self.last_args.lock().unwrap().clear();
                self.release_driver();
            }
            self.set_state("waiting", "ждёт запуска приложения из whitelist");
            *self.last_pids.lock().unwrap() = pids;
            return;
        }

        // Стратегия не разобралась (пустые аргументы) — запускать winws.exe без фильтров
        // бессмысленно. Причину показываем в интерфейсе.
        if strategy_args.is_empty() {
            let detail = self
                .args_error
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "не удалось разобрать выбранную стратегию".to_string());
            self.set_state("no_args", detail);
            return;
        }

        let mut full_args: Vec<String> = Vec::new();
        if let Some(idx) = *self.iface_pin.lock().unwrap() {
            full_args.push(format!("--wf-iface={idx}"));
        }
        full_args.extend_from_slice(strategy_args);

        // Если процесс уже умер — запоминаем, чем он закончил (код + хвост лога).
        let exit_note = {
            let mut g = self.child.lock().unwrap();
            match g.as_mut() {
                Some(c) => match c.try_wait() {
                    Ok(Some(st)) => Some(match st.code() {
                        Some(code) => format!("winws.exe завершился с кодом {code}"),
                        None => "winws.exe завершён".to_string(),
                    }),
                    _ => None,
                },
                None => None,
            }
        };
        if let Some(note) = exit_note {
            let tail = self.log_tail(3);
            self.set_state("exited", if tail.is_empty() { note } else { format!("{note}: {tail}") });
        }

        let alive = self.is_running();
        let args_changed = *self.last_args.lock().unwrap() != full_args;
        if alive && !args_changed {
            self.set_state("running", "перехват трафика активен");
            *self.last_pids.lock().unwrap() = pids;
            return;
        }

        // Если процесс упал сам — не долбимся перезапусками чаще раза в 10 секунд
        // (состояние "exited"/"error" при этом остаётся видимым в интерфейсе).
        if !alive && !args_changed {
            if let Some(t) = *self.last_spawn.lock().unwrap() {
                if t.elapsed() < Duration::from_secs(10) {
                    return;
                }
            }
        }

        self.stop_locked();
        *self.last_spawn.lock().unwrap() = Some(std::time::Instant::now());
        match self.spawn(&full_args) {
            Ok(child) => {
                *self.child.lock().unwrap() = Some(child);
                *self.last_args.lock().unwrap() = full_args;
                self.set_state("starting", "запускаю winws.exe…");
            }
            Err(e) => {
                let msg = format!("не удалось запустить winws.exe: {e}");
                Self::push_log(&self.logs, format!("[zapret] {msg}"));
                self.set_state("error", msg);
            }
        }
        *self.last_pids.lock().unwrap() = pids;
    }
}

/// Фоновый цикл, вызывается из main.rs через tauri::async_runtime::spawn.
/// Интервал 2с — компромисс между отзывчивостью (открыли браузер — обход подхватился
/// быстро) и лишними перезапусками winws.exe (у него есть небольшой стоимостной оверхед
/// на установку WinDivert-хендла).
pub async fn watch_loop(
    manager: std::sync::Arc<ZapretManager>,
    get_whitelist: impl Fn() -> Vec<String> + Send + 'static,
    get_strategy_args: impl Fn() -> Vec<String> + Send + 'static,
) {
    loop {
        let whitelist = get_whitelist();
        let args = get_strategy_args();
        manager.tick(&whitelist, &args);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Запускает `sc.exe` без окна и возвращает код выхода.
fn sc(args: &[&str]) -> Option<i32> {
    let mut cmd = Command::new("sc");
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.status().ok().and_then(|s| s.code())
}

/// Человекочитаемый итог команды sc по её коду выхода.
fn describe_sc(label: &str, code: Option<i32>) -> String {
    match code {
        Some(0) => format!("{label}: выполнено"),
        Some(1060) => format!("{label}: такой службы нет"),
        Some(1062) => format!("{label}: уже остановлена"),
        Some(1072) => format!("{label}: помечена на удаление (исчезнет после закрытия последнего дескриптора)"),
        Some(c) => format!("{label}: код {c}"),
        None => format!("{label}: не удалось запустить sc.exe"),
    }
}
