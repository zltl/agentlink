//! `agentlink-gui` Windows GUI-subsystem launcher (zero console flash for Tray & Controller).
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    agentlink_cli::run_gui_main();
}
