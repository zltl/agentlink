//! Windows service control for `--scope system`.
//!
//! User scope is the notification-area tray with an HKCU Run entry. This
//! service runs in session 0 and cannot see the interactive desktop.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio_util::sync::CancellationToken;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::node_cfg::{self, NodeArgs};
use crate::service::NODE_NAME;

static DATA_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
const MAX_SERVICE_LOG_BYTES: u64 = 5 * 1024 * 1024;
const SCM_DELETE_WAIT: Duration = Duration::from_secs(10);

define_windows_service!(ffi_service_main, service_main);

pub fn run_dispatcher(data_dir: Option<PathBuf>) -> Result<()> {
    let _ = DATA_DIR.set(data_dir);
    service_dispatcher::start(NODE_NAME, ffi_service_main)
        .map_err(|err| anyhow!("service dispatcher: {err}"))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service() {
        eprintln!("agentlink service: {err:#}");
    }
}

fn run_service() -> Result<()> {
    let data_dir = DATA_DIR.get().and_then(|dir| dir.clone());
    let config = node_cfg::load(NodeArgs {
        relay: None,
        fingerprint: None,
        trust: None,
        invite: None,
        name: None,
        pairing_token: None,
        data_dir,
        root: None,
        max_access: None,
        stream_consent: None,
    })?;
    init_log(&config.data_dir);
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            signal.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(NODE_NAME, handler)
        .map_err(|err| anyhow!("register service handler: {err}"))?;
    status_handle
        .set_service_status(status_of(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
        ))
        .map_err(|err| anyhow!("mark service running: {err}"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    let result = runtime.block_on(agentlink_node::run(config, shutdown));
    let code = u32::from(result.is_err());
    let _ = status_handle.set_service_status(status_of(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        code,
    ));
    result.map(|_| ()).map_err(|err| anyhow!(err))
}

struct RotatingLogInner {
    path: PathBuf,
    file: Option<File>,
    written: u64,
}

impl RotatingLogInner {
    fn open(path: PathBuf) -> Self {
        let written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut inner = Self {
            path,
            file: None,
            written,
        };
        inner.maybe_rotate();
        inner.reopen();
        inner
    }

    fn reopen(&mut self) {
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
        self.written = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
    }

    fn maybe_rotate(&mut self) {
        if self.written < MAX_SERVICE_LOG_BYTES {
            return;
        }
        self.file = None;
        let backup = self.path.with_extension("log.1");
        let _ = std::fs::remove_file(&backup);
        let _ = std::fs::rename(&self.path, &backup);
        self.written = 0;
        self.reopen();
    }
}

#[derive(Clone)]
struct RotatingLogWriter {
    inner: Arc<Mutex<RotatingLogInner>>,
}

impl Write for RotatingLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.maybe_rotate();
        if guard.file.is_none() {
            guard.reopen();
        }
        if let Some(file) = guard.file.as_mut() {
            let n = file.write(buf)?;
            guard.written = guard.written.saturating_add(n as u64);
            Ok(n)
        } else {
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(file) = guard.file.as_mut() {
            file.flush()?;
        }
        Ok(())
    }
}

fn init_log(data_dir: &Path) {
    let _ = std::fs::create_dir_all(data_dir);
    let writer = RotatingLogWriter {
        inner: Arc::new(Mutex::new(RotatingLogInner::open(
            data_dir.join("service.log"),
        ))),
    };
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .try_init();
}

fn status_of(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: if code == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(code)
        },
        checkpoint: 0,
        wait_hint: Duration::from_secs(15),
        process_id: None,
    }
}

fn wait_for_service_deletion() {
    let deadline = Instant::now() + SCM_DELETE_WAIT;
    while service_exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn install_service(binary: &Path, data_dir: &Path) -> Result<()> {
    let _ = stop_service();
    let _ = uninstall_service();
    wait_for_service_deletion();
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|err| anyhow!("open service manager: {err}"))?;
    let info = ServiceInfo {
        name: OsString::from(NODE_NAME),
        display_name: OsString::from("agentlink node"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary.to_path_buf(),
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("run"),
            OsString::from("--data-dir"),
            OsString::from(data_dir.as_os_str()),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    let deadline = Instant::now() + SCM_DELETE_WAIT;
    loop {
        match manager.create_service(&info, ServiceAccess::START) {
            Ok(_) => return Ok(()),
            Err(err) => {
                let text = err.to_string();
                let marked_for_delete =
                    text.contains("1072") || text.to_ascii_lowercase().contains("marked for deletion");
                if marked_for_delete && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(250));
                    continue;
                }
                return Err(anyhow!("create Windows service: {err}"));
            }
        }
    }
}

pub fn start_service() -> Result<()> {
    let service = open(ServiceAccess::START)?;
    service
        .start(&[] as &[&OsStr])
        .map_err(|err| anyhow!("start Windows service: {err}"))
}

pub fn stop_service() -> Result<()> {
    if !service_exists() {
        return Ok(());
    }
    let service = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    let state = service
        .query_status()
        .map(|status| status.current_state)
        .unwrap_or(ServiceState::Stopped);
    if state == ServiceState::Stopped {
        return Ok(());
    }
    service
        .stop()
        .map_err(|err| anyhow!("stop Windows service: {err}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(status) = service.query_status() {
            if status.current_state == ServiceState::Stopped {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    if !service_exists() {
        return Ok(());
    }
    let _ = stop_service();
    let service = open(ServiceAccess::DELETE | ServiceAccess::STOP)?;
    service
        .delete()
        .map_err(|err| anyhow!("delete Windows service: {err}"))?;
    Ok(())
}

pub fn service_exists() -> bool {
    open(ServiceAccess::QUERY_STATUS).is_ok()
}

pub fn service_running() -> bool {
    open(ServiceAccess::QUERY_STATUS)
        .and_then(|service| service.query_status().map_err(|err| anyhow!("{err}")))
        .map(|status| status.current_state == ServiceState::Running)
        .unwrap_or(false)
}

fn open(access: ServiceAccess) -> Result<windows_service::service::Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| anyhow!("open service manager: {err}"))?;
    manager
        .open_service(NODE_NAME, access)
        .map_err(|err| anyhow!("open service {NODE_NAME}: {err}"))
}
