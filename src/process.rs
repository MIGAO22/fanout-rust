use anyhow::{anyhow, bail, Context, Result};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex as StdMutex, RwLock,
    },
    thread,
    time::Duration,
};

use tokio::{
    process::Child,
    sync::{watch, Mutex, Notify},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

/// The namespace captured at fanout startup. Commands and newly spawned
/// processes must start here, never in a namespace borrowed by a dialer.
#[cfg(target_os = "linux")]
static MAIN_NETNS: RwLock<Option<Arc<File>>> = RwLock::new(None);

/// Capture the host network namespace. Call once, before starting any tunnel.
///
/// Other platforms have no Linux `setns`; their command helpers use the normal
/// process namespace so this crate remains compilable there.
pub fn init_main_netns() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let file = File::open("/proc/thread-self/ns/net").context("记录母机网络命名空间失败")?;
        let mut slot = MAIN_NETNS
            .write()
            .map_err(|_| anyhow!("母机网络命名空间锁已损坏"))?;
        *slot = Some(Arc::new(file));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = ();
    Ok(())
}

#[cfg(target_os = "linux")]
fn captured_main_netns() -> Result<Option<Arc<File>>> {
    let slot = MAIN_NETNS
        .read()
        .map_err(|_| anyhow!("母机网络命名空间锁已损坏"))?;
    Ok(slot.as_ref().cloned())
}

/// Run a closure on a dedicated OS thread in the captured host namespace.
///
/// A fresh thread is important: Rust's runtime never migrates a std thread onto
/// another task, and the thread terminates after `function` returns. If setns
/// fails, it is deliberately not unlocked or returned to any worker pool.
///
/// Before initialization this preserves the Go fallback and calls `function`
/// directly. Production startup must call [`init_main_netns`] first.
pub fn in_main_netns<T, F>(function: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send,
    T: Send,
{
    #[cfg(target_os = "linux")]
    {
        let Some(main) = captured_main_netns()? else {
            return function();
        };

        let (sender, receiver) = mpsc::channel::<Result<T>>();
        thread::scope(|scope| {
            thread::Builder::new()
                .name("fanout-host-netns".into())
                .spawn_scoped(scope, move || {
                    // A std thread is affinely tied to this OS thread and dies
                    // after the closure; it can never re-enter a worker pool.
                    if let Err(error) = enter_netns(&main) {
                        let error = anyhow::Error::new(error).context("切回母机网络命名空间失败");
                        let _ = sender.send(Err(error));
                        return;
                    }
                    let _ = sender.send(function());
                })
                .context("启动母机网络命名空间线程失败")?;

            receiver
                .recv()
                .context("母机网络命名空间线程异常退出")?
        })
    }

    #[cfg(not(target_os = "linux"))]
    function()
}

#[cfg(target_os = "linux")]
pub(crate) fn enter_netns(file: &File) -> io::Result<()> {
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Run a configured command in the host namespace.
pub fn run_command(command: &mut Command) -> Result<()> {
    in_main_netns(move || command.run().context("执行命令失败"))
}

/// Start a configured long-lived process in the host namespace.
pub fn start_command(command: &mut Command) -> Result<std::process::Child> {
    in_main_netns(move || command.spawn().context("启动子进程失败"))
}

/// Start a Tokio process in the host namespace. The returned child can be
/// awaited without moving the calling task into a foreign namespace.
pub fn start_tokio_command(command: &mut tokio::process::Command) -> Result<tokio::process::Child> {
    let runtime = tokio::runtime::Handle::try_current()
        .context("启动 Tokio 子进程需要 Tokio 运行时")?;
    in_main_netns(move || {
        // Tokio's non-pidfd Unix backend needs the runtime's signal driver.
        let _runtime_guard = runtime.enter();
        command.spawn().context("启动子进程失败")
    })
}

fn output_unchecked(command: &mut Command) -> Result<Output> {
    in_main_netns(move || command.output().context("读取命令输出失败"))
}

fn combined_output_unchecked(command: &mut Command) -> Result<Output> {
    in_main_netns(move || command.combined_output().context("读取命令输出失败"))
}

fn command_parts(command: &Command) -> (String, Vec<String>) {
    (
        command.get_program().to_string_lossy().into_owned(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
    )
}

fn ensure_success(command: &Command, output: &Output, combined: bool) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let (program, args) = command_parts(command);
    let details = if combined {
        output.stdout.as_slice()
    } else {
        output.stderr.as_slice()
    };
    bail!(
        "{}",
        format_command_error(&program, &args, &output.status, details)
    );
}

/// Execute in the host namespace, returning stdout/stderr only on success.
pub fn output_command(program: &str, args: &[String]) -> Result<Output> {
    let mut command = Command::new(program);
    command.args(args);
    let output = output_unchecked(&mut command)?;
    ensure_success(&command, &output, false)?;
    Ok(output)
}

/// Execute in the host namespace, returning merged stdout/stderr on success.
pub fn combined_output_command(program: &str, args: &[String]) -> Result<Output> {
    let mut command = Command::new(program);
    command.args(args);
    let output = combined_output_unchecked(&mut command)?;
    ensure_success(&command, &output, true)?;
    Ok(output)
}

/// Execute a command and preserve fanout's `program args: status: output`
/// diagnostic shape, including combined output on failure.
pub fn run_formatted(program: &str, args: &[String]) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args);
    let output = combined_output_unchecked(&mut command)?;
    ensure_success(&command, &output, true)
}

pub fn run_quiet(program: &str, args: &[String]) {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = run_command(&mut command);
}

/// A compact Rust process spawn helper for callers that do not want inherited
/// stdin. It still crosses the host-namespace guard.
pub fn spawn_detached(program: &str, args: &[String]) -> Result<std::process::Child> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    start_command(&mut command)
}

pub fn format_exit_status(status: &ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exit status {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("signal: {signal}");
        }
    }
    status.to_string()
}

pub fn format_command_error(
    program: &str,
    args: &[String],
    status: &ExitStatus,
    output: &[u8],
) -> String {
    format!(
        "{} {}: {}: {}",
        program,
        args.join(" "),
        format_exit_status(status),
        String::from_utf8_lossy(output).trim()
    )
}

#[derive(Clone, Debug)]
pub struct ProcessExit {
    pub result: Result<(), String>,
}

struct OvpnInner {
    child: Mutex<Child>,
    pid: u32,
    stopped: AtomicBool,
    stop_notify: Notify,
    exit: watch::Sender<Option<ProcessExit>>,
    dead_why: StdMutex<Option<String>>,
}

/// A shared OpenVPN child handle with a replayable exit event.
///
/// One background task owns `wait()`. Both readiness checks and the later
/// health watcher can subscribe without stealing the exit result from each
/// other. Clones refer to the same process and the same first-wins death reason.
#[derive(Clone)]
pub struct OvpnProc {
    inner: Arc<OvpnInner>,
}

impl OvpnProc {
    /// Adopt a child and start its single background waiter. Requires a Tokio
    /// runtime; the child must already have been spawned via the host guard.
    pub fn from_child(child: Child) -> Result<Self> {
        tokio::runtime::Handle::try_current()
            .context("创建 openvpn 进程句柄需要 Tokio 运行时")?;

        let (exit, _) = watch::channel(None);
        let pid = child.id();
        let inner = Arc::new(OvpnInner {
            child: Mutex::new(child),
            pid,
            stopped: AtomicBool::new(false),
            stop_notify: Notify::new(),
            exit,
            dead_why: StdMutex::new(None),
        });

        let wait_child = Arc::clone(&inner);
        tokio::spawn(async move {
            let mut child = wait_child.child.lock().await;
            let killed = wait_child.stop_notify.notified();
            let result = if wait_child.stopped.load(Ordering::Acquire) {
                let _ = child.start_kill();
                child.wait().await
            } else {
                tokio::select! {
                    result = child.wait() => result,
                    _ = killed => {
                        let _ = child.start_kill();
                        child.wait().await
                    }
                }
            };
            let result = match result {
                Ok(status) if status.success() => Ok(()),
                Ok(status) => Err(format_exit_status(&status)),
                Err(error) => Err(error.to_string()),
            };
            // The sender lives in `inner`, so this value remains replayable
            // after every receiver has been dropped.
            let _ = wait_child.exit.send(Some(ProcessExit { result }));
        });

        Ok(Self { inner })
    }

    /// Wait for the process exit. Safe to call more than once or concurrently.
    pub async fn wait_for_exit(&self) -> Result<(), String> {
        let mut receiver = self.inner.exit.subscribe();
        loop {
            if let Some(exit) = receiver.borrow().clone() {
                return exit.result;
            }
            receiver
                .changed()
                .await
                .map_err(|_| "openvpn 退出等待器已关闭".to_string())?;
        }
    }

    /// Mark an intentional stop before signalling the background waiter.
    /// Idempotent; the child is killed exactly through that waiter.
    pub fn kill(&self) {
        if !self.inner.stopped.swap(true, Ordering::AcqRel) {
            self.inner.stop_notify.notify_one();
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::Acquire)
    }

    pub fn pid(&self) -> Option<u32> {
        (self.inner.pid != 0).then_some(self.inner.pid)
    }

    /// Record why the process died. Only the first caller wins.
    pub fn mark_dead(&self, why: impl Into<String>) {
        let mut slot = self
            .inner
            .dead_why
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_none() {
            *slot = Some(why.into());
        }
    }

    pub fn dead_reason(&self) -> Option<String> {
        self.inner
            .dead_why
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Watch an already-ready tunnel's process. Intentional stops stay quiet.
    pub async fn watch_ovpn_exit(&self, log_path: &Path) {
        if self.is_stopped() {
            return;
        }
        let stopped = self.inner.stop_notify.notified();
        tokio::select! {
            result = self.wait_for_exit() => {
                if self.is_stopped() {
                    return;
                }
                let mut why = String::from("openvpn 进程已退出");
                if let Err(error) = result {
                    why.push_str("：");
                    why.push_str(&error);
                }
                let hint = ovpn_log_hint(log_path);
                if !hint.is_empty() {
                    why.push('（');
                    why.push_str(&hint);
                    why.push('）');
                }
                self.mark_dead(one_line(&why, 220));
            }
            _ = stopped => {}
        }
    }
}

/// Build the argv used to launch OpenVPN inside a namespace. The host guard
/// still wraps the actual spawn, so `ip netns exec` itself starts in the host.
pub fn openvpn_argv(namespace: &str, binary: &str, args: &[String]) -> Vec<String> {
    let mut argv = vec![
        "ip".into(),
        "netns".into(),
        "exec".into(),
        namespace.into(),
        binary.into(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// Spawn `ip netns exec <namespace> <binary> <args...>` from the host namespace.
/// The caller owns config/auth/log paths and version/WARP-specific arguments.
pub async fn spawn_openvpn_in_netns(
    namespace: &str,
    binary: &str,
    args: &[String],
) -> Result<OvpnProc> {
    let argv = openvpn_argv(namespace, binary, args);
    let mut command = tokio::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let child = start_tokio_command(&mut command).context("启动 openvpn 失败")?;
    OvpnProc::from_child(child).context("启动 openvpn 失败")
}

/// OpenVPN keepalive and bounded-retry arguments from the Go implementation.
pub fn ovpn_tuning(budget: Duration, mssfix: i32) -> Vec<String> {
    let hand_window = ((budget.as_secs_f64() / 3.0) as i64).clamp(5, 20);
    vec![
        "--keepalive".into(),
        "15".into(),
        "45".into(),
        "--hand-window".into(),
        hand_window.to_string(),
        "--tls-timeout".into(),
        "1".into(),
        "--connect-timeout".into(),
        "15".into(),
        "--connect-retry".into(),
        "3".into(),
        "30".into(),
        "--connect-retry-max".into(),
        "3".into(),
        "--resolv-retry".into(),
        "3".into(),
        "--remote-random".into(),
        "--mssfix".into(),
        mssfix.to_string(),
    ]
}

const OVPN_OWN_FAULTS: &[(&str, &str)] = &[
    ("message too long", "外层包超过链路 MTU"),
    ("emsgsize", "外层包超过链路 MTU"),
    (
        "failed to negotiate cipher",
        "数据通道算法和节点谈不拢（开着 AEAD-only 就先关掉再试）",
    ),
    (
        "pushed compression settings",
        "节点要求开压缩，AEAD-only 不让开",
    ),
    ("options error", "参数没被接受"),
    ("unrecognized option", "参数没被接受"),
];

const OVPN_NODE_FAULTS: &[(&str, &str)] = &[
    ("certificate has expired", "节点证书过期"),
    ("verify error", "节点证书校验不过"),
    ("auth_failed", "节点拒绝了用户名/密码"),
    ("authentication failed", "节点拒绝了用户名/密码"),
    ("ssl alert:", "节点在 TLS 层直接拒绝（见原文）"),
    ("tls_error", "TLS 握手没走完"),
    ("tls handshake failed", "TLS 握手没走完"),
    ("cannot resolve host address", "节点域名解析不出来"),
    ("network is unreachable", "母机到节点没有路由"),
    ("no route to host", "母机到节点没有路由"),
    ("connection reset", "节点掐了连接"),
    ("connection timed out", "节点的端口没应答"),
    ("peer connection initiated", "节点已应答，卡在后面的步骤"),
];

fn why_here(table: &[(&str, &str)], lower: &str) -> Option<&'static str> {
    table
        .iter()
        .find_map(|(needle, why)| lower.contains(needle).then_some(*why))
}

/// Pick the actionable OpenVPN log line. Local link/option faults outrank node
/// faults; within the node class, the last matching line is the latest remote.
pub fn ovpn_error_line(log: &str) -> String {
    let mut own = String::new();
    let mut node = String::new();
    for line in log.lines() {
        let lower = line.to_lowercase();
        if let Some(why) = why_here(OVPN_OWN_FAULTS, &lower) {
            own = format!("{why}：{}", line.trim());
        } else if let Some(why) = why_here(OVPN_NODE_FAULTS, &lower) {
            node = format!("{why}：{}", line.trim());
        }
    }
    one_line(if !own.is_empty() { &own } else { &node }, 220)
}

/// Read only the last 64 KiB of an OpenVPN log and extract its best hint.
pub fn ovpn_log_hint(path: &Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let Ok(metadata) = file.metadata() else {
        return String::new();
    };
    if metadata.len() == 0 {
        return String::new();
    }

    const SPAN: u64 = 64 << 10;
    let offset = metadata.len().saturating_sub(SPAN);
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::with_capacity((metadata.len() - offset).min(SPAN) as usize);
    if file.take(SPAN).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    ovpn_error_line(&String::from_utf8_lossy(&bytes))
}

/// Collapse whitespace and truncate by Unicode characters, adding an ellipsis.
fn one_line(value: &str, max: usize) -> String {
    let flat = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let mut shortened: String = flat.chars().take(max).collect();
    shortened.push('…');
    shortened
}

/// Paths for the three per-tunnel files. Writing them remains the tunnel's job.
pub fn openvpn_paths(work_dir: &Path, namespace: &str) -> (PathBuf, PathBuf, PathBuf) {
    (
        work_dir.join(format!("{namespace}.ovpn")),
        work_dir.join("auth.txt"),
        work_dir.join(format!("{namespace}.log")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_error_keeps_program_status_and_output() {
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(9 << 8)
        };
        #[cfg(not(unix))]
        let status = ExitStatus::from_raw(9);

        let error = format_command_error(
            "ip",
            &["route".into(), "replace".into(), "1.2.3.4/32".into()],
            &status,
            b"  Network is unreachable\n",
        );
        assert!(error.starts_with("ip route replace 1.2.3.4/32: "));
        assert!(error.contains("exit status 9"));
        assert!(error.ends_with(": Network is unreachable"));
    }
}
