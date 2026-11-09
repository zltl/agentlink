//! Desktop controller for Windows and glibc Linux.
//!
//! Musl release binaries stay headless. `agentlink controller` on those builds
//! explains how to compile the window.

mod autostart;
mod model;

#[cfg(not(target_env = "musl"))]
mod chrome;
#[cfg(all(unix, not(target_env = "musl")))]
mod debug;
#[cfg(not(target_env = "musl"))]
mod decode;
#[cfg(not(target_env = "musl"))]
mod indicator;
#[cfg(not(target_env = "musl"))]
mod theme;
#[cfg(not(target_env = "musl"))]
mod ui;
#[cfg(not(target_env = "musl"))]
mod viewport;
#[cfg(not(target_env = "musl"))]
mod worker;

pub fn available() -> bool {
    cfg!(not(target_env = "musl"))
}

pub struct EnterArgs {
    pub config_dir: std::path::PathBuf,
    pub data_dir: Option<std::path::PathBuf>,
    pub tray: bool,
    pub background: bool,
    pub check: bool,
    pub debug_socket: Option<std::path::PathBuf>,
    pub mock: bool,
    pub headless: bool,
    pub fail_connect: bool,
    pub connect_timeout_secs: u64,
    pub max_fps: u32,
    pub perf_log: Option<std::path::PathBuf>,
    /// Open this node's desktop once the machine list arrives.
    pub open_desktop: Option<String>,
}

pub fn enter(
    config_dir: std::path::PathBuf,
    data_dir: Option<std::path::PathBuf>,
    tray: bool,
    background: bool,
    check: bool,
) -> i32 {
    enter_args(EnterArgs {
        config_dir,
        data_dir,
        tray,
        background,
        check,
        debug_socket: None,
        mock: false,
        headless: false,
        fail_connect: false,
        connect_timeout_secs: 12,
        max_fps: 30,
        perf_log: None,
        open_desktop: None,
    })
}

pub fn enter_args(args: EnterArgs) -> i32 {
    if args.check {
        if available() {
            println!("controller: ready");
            return 0;
        }
        println!("controller: unavailable");
        eprintln!(
            "this build has no desktop window. On Linux, build the glibc binary: cargo build -p agentlink-cli"
        );
        return 1;
    }
    #[cfg(not(target_env = "musl"))]
    {
        let data_dir = match args.data_dir {
            Some(path) => path,
            None => match crate::tray::resolve_data_dir(None) {
                Ok(path) => path,
                Err(err) => {
                    eprintln!("{err}");
                    return 1;
                }
            },
        };
        #[cfg(unix)]
        if let Some(socket) = args.debug_socket {
            return debug::enter_debug(
                args.config_dir,
                data_dir,
                args.tray,
                args.background,
                debug::DebugOpts {
                    socket,
                    mock: args.mock,
                    headless: args.headless,
                    fail_connect: args.fail_connect,
                    connect_timeout_secs: args.connect_timeout_secs,
                    max_fps: args.max_fps,
                    perf_log: args.perf_log.clone(),
                },
            );
        }
        #[cfg(not(unix))]
        if args.debug_socket.is_some() || args.headless {
            eprintln!("controller debug socket requires unix");
            return 1;
        }
        if args.headless {
            eprintln!("controller --headless requires --debug-socket");
            return 1;
        }
        if args.mock {
            return ui::enter_with_opts(ui::EnterOpts {
                config_dir: args.config_dir,
                data_dir,
                tray: args.tray,
                background: args.background,
                mock: true,
                headless: false,
                fail_connect: args.fail_connect,
                connect_timeout_secs: args.connect_timeout_secs,
                max_fps: args.max_fps,
                perf_log: args.perf_log,
                debug_inbox: None,
                logical_size: (1440.0, 900.0),
                open_desktop: args.open_desktop.clone(),
            });
        }
        return ui::enter_with_opts(ui::EnterOpts {
            config_dir: args.config_dir,
            data_dir,
            tray: args.tray,
            background: args.background,
            mock: false,
            headless: false,
            fail_connect: false,
            connect_timeout_secs: args.connect_timeout_secs,
            max_fps: args.max_fps,
            perf_log: args.perf_log,
            debug_inbox: None,
            logical_size: (1080.0, 760.0),
            open_desktop: args.open_desktop.clone(),
        });
    }
    #[cfg(target_env = "musl")]
    {
        let _ = args;
        eprintln!(
            "this build has no desktop window. On Linux, build the glibc binary: cargo build -p agentlink-cli"
        );
        1
    }
}
