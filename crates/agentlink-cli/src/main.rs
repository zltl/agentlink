//! `agentlink` console CLI binary: relay, node, CLI, and MCP server.
//!
//! Deliberately uses the default console subsystem on Windows so PowerShell
//! capture (`$x = & agentlink ls`), `cmd.exe`, pipes, and `agentlink shell`
//! work natively without detaching or dropping stdout/stderr. Zero-console-flash
//! Windows Tray and Controller GUI launches use the sibling `agentlink-gui.exe`
//! binary (`src/bin/agentlink_gui.rs`).

fn main() {
    agentlink_cli::run_main();
}
