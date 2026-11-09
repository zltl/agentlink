//! Windows service control for `--scope system`.
//!
//! User scope is the notification-area tray with an HKCU Run entry. This
//! service runs in session 0 and cannot see the interactive desktop.

use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

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

fn init_log(data_dir: &Path) {
    let _ = std::fs::create_dir_all(data_dir);
    let Ok(file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("service.log"))
    else {
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || file.try_clone().expect("service log"))
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

pub fn install_service(binary: &Path, data_dir: &Path) -> Result<()> {
    let _ = stop_service();
    let _ = uninstall_service();
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
    let _service = manager
        .create_service(&info, ServiceAccess::START)
        .map_err(|err| anyhow!("create Windows service: {err}"))?;
    Ok(())
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
