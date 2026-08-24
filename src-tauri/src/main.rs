#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State, WindowEvent};

#[cfg(target_os = "windows")]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

struct AppState {
    port: Arc<AtomicU16>,
    auth_token: String,
}

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("无法绑定随机端口");
    listener.local_addr().unwrap().port()
}

fn generate_auth_token() -> String {
    use std::fmt::Write;
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn resolve_core_path() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_dir = current_exe.parent().ok_or("无法获取可执行目录")?;

    let prod_candidate = exe_dir.join("opensight-core.exe");
    if prod_candidate.is_file() {
        return Ok(prod_candidate);
    }

    let onedir_candidate = exe_dir.join("opensight-core").join("opensight-core.exe");
    if onedir_candidate.is_file() {
        return Ok(onedir_candidate);
    }

    let dev_candidate = PathBuf::from("../dist/OpenSight/opensight-core/opensight-core.exe");
    if dev_candidate.is_file() {
        return Ok(dev_candidate);
    }

    Err("未在受信任路径下找到 opensight-core 核心文件".to_string())
}

#[cfg(target_os = "windows")]
fn bind_pid_to_job_object(pid: u32) {
    unsafe {
        let job = CreateJobObjectW(None, None).unwrap();
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let _ = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        if let Ok(process_handle) = windows::Win32::System::Threading::OpenProcess(
            windows::Win32::System::Threading::PROCESS_SET_QUOTA | windows::Win32::System::Threading::PROCESS_TERMINATE,
            false,
            pid,
        ) {
            let _ = AssignProcessToJobObject(job, process_handle);
        }
    }
}

fn wait_for_backend_ready(port: u16) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(8) {
        if TcpListener::bind(format!("127.0.0.1:{}", port)).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[tauri::command]
fn get_backend_port(state: State<'_, AppState>) -> u16 {
    state.port.load(Ordering::SeqCst)
}

#[tauri::command]
fn get_auth_token(state: State<'_, AppState>) -> String {
    state.auth_token.clone()
}

fn main() {
    let port = get_free_port();
    let port_holder = Arc::new(AtomicU16::new(port));
    let auth_token = generate_auth_token();

    if let Ok(core_exe) = resolve_core_path() {
        let child = Command::new(&core_exe)
            .arg("--port")
            .arg(port.to_string())
            .arg("--auth-token")
            .arg(&auth_token)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        if let Ok(c) = child {
            #[cfg(target_os = "windows")]
            bind_pid_to_job_object(c.id());
        }
    }

    let _ready = wait_for_backend_ready(port);

    tauri::Builder::default()
        .manage(AppState {
            port: Arc::clone(&port_holder),
            auth_token,
        })
        .invoke_handler(tauri::generate_handler![get_backend_port, get_auth_token])
        .setup(|app| {
            let show_i = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, "hide", "最小化到托盘", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "退出 OpenSight", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &hide_i, &quit_i])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip("OpenSight VPN 3.2");

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }

            tray_builder
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            if window.is_visible().unwrap_or(false) {
                                let _ = window.hide();
                            } else {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // 点击关闭时静默隐藏到托盘，保持后台守护与分流路由不中断
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("运行 Tauri 应用失败");
}
