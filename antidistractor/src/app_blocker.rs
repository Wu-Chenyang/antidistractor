//! App blocker — 使用 fanotify FAN_OPEN_EXEC_PERM 阻止特定应用启动。
//!
//! 监听整个文件系统的 exec 事件（FAN_MARK_FILESYSTEM），对 blocklist 中的路径或
//! 进程名（basename）回复 FAN_DENY，使进程收到 EACCES 无法启动。

use std::collections::HashSet;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use libc::{
    AT_FDCWD,
    O_LARGEFILE, O_RDONLY,
    close, read, write,
    fanotify_init, fanotify_mark,
    FAN_CLASS_CONTENT, FAN_CLOEXEC,
    FAN_OPEN_EXEC_PERM,
    FAN_MARK_ADD, FAN_MARK_FILESYSTEM,
    FAN_ALLOW, FAN_DENY,
};

/// 被屏蔽的应用集合。可在 control server 处理命令时动态修改。
#[derive(Default)]
pub struct BlockedSet {
    /// 精确可执行文件路径，如 "/usr/bin/steam"
    pub paths: HashSet<String>,
    /// 进程名（basename），如 "WeChat"、"steam"
    pub names: HashSet<String>,
}

impl BlockedSet {
    pub fn is_blocked(&self, path: &str) -> bool {
        if self.paths.contains(path) {
            return true;
        }
        // basename 匹配
        if let Some(name) = std::path::Path::new(path).file_name() {
            if let Some(s) = name.to_str() {
                return self.names.contains(s);
            }
        }
        false
    }
}

/// fanotify 事件头，与 `struct fanotify_event_metadata` 对应
#[repr(C)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// fanotify 响应，与 `struct fanotify_response` 对应
#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

const META_SIZE: usize = std::mem::size_of::<FanotifyEventMetadata>();

pub struct AppBlocker {
    fan_fd: RawFd,
    pub blocked: Arc<Mutex<BlockedSet>>,
}

impl AppBlocker {
    /// 仅创建 fanotify fd，不注册 mark（mark 在 run() 中进行，避免 new() 阶段死锁）。
    pub fn new() -> anyhow::Result<Self> {
        let fan_fd = unsafe {
            fanotify_init(
                (FAN_CLASS_CONTENT | FAN_CLOEXEC) as u32,
                (O_RDONLY | O_LARGEFILE) as u32,
            )
        };
        if fan_fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!("fanotify_init failed: {e}"));
        }

        log::info!("[app-blocker] fanotify fd created (mark will be set in run thread)");

        Ok(Self {
            fan_fd,
            blocked: Arc::new(Mutex::new(BlockedSet::default())),
        })
    }

    /// 同步阻塞循环，在独立线程（std::thread::spawn）中运行。
    /// 在线程内部才注册 FAN_MARK_FILESYSTEM，确保 mark 之前的 exec 不被拦截。
    /// 自身 PID 的 exec 事件（notify-send 等）一律 ALLOW，防止死锁。
    pub fn run(self) {
        // 在线程内部注册 mark，避免主线程初始化期间的死锁
        let root = std::ffi::CString::new("/").unwrap();
        let ret = unsafe {
            fanotify_mark(
                self.fan_fd,
                (FAN_MARK_ADD | FAN_MARK_FILESYSTEM) as u32,
                FAN_OPEN_EXEC_PERM as u64,
                AT_FDCWD,
                root.as_ptr(),
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            log::error!("[app-blocker] fanotify_mark failed: {e}");
            return;
        }
        log::info!("[app-blocker] watching all exec events (FAN_MARK_FILESYSTEM)");

        let my_pid = unsafe { libc::getpid() };
        let mut buf = vec![0u8; 4096];

        loop {
            let n = unsafe {
                read(self.fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n <= 0 {
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    log::error!("[app-blocker] read error: {e}");
                }
                continue;
            }
            let n = n as usize;

            let mut off = 0usize;
            while off + META_SIZE <= n {
                // SAFETY: buf 是我们自己的缓冲区，按 FanotifyEventMetadata 解释
                let meta = unsafe {
                    &*(buf.as_ptr().add(off) as *const FanotifyEventMetadata)
                };
                let ev_len = meta.event_len as usize;
                let ev_fd  = meta.fd;
                let mask   = meta.mask;
                let ev_pid = meta.pid;

                off += if ev_len > 0 { ev_len } else { META_SIZE };

                // 权限事件必须有合法 fd
                if ev_fd < 0 {
                    continue; // overflow event，无 fd
                }

                // 自身进程的 exec 事件（包括 tokio runtime、notify-send 等）一律 ALLOW
                // 必须在读取路径之前处理，否则会在 readlink 时形成死锁
                if ev_pid == my_pid {
                    self.respond(ev_fd, FAN_ALLOW as u32);
                    unsafe { close(ev_fd) };
                    continue;
                }

                if mask & (FAN_OPEN_EXEC_PERM as u64) == 0 {
                    // 非 exec 权限事件，直接 allow
                    self.respond(ev_fd, FAN_ALLOW as u32);
                    unsafe { close(ev_fd) };
                    continue;
                }

                // 读取被执行的文件路径。
                // 通过 event_fd 指向的 /proc/self/fd/<ev_fd> 读取路径（readlink）。
                // 用 libc::readlinkat 直接调用，避免 std::fs 可能的额外开销。
                // ev_fd 本身就是被执行文件的 fd，readlink 不会阻塞。
                let exec_path = {
                    let mut path_buf = vec![0u8; 4096];
                    let link = format!("/proc/self/fd/{ev_fd}\0");
                    let n = unsafe {
                        libc::readlink(
                            link.as_ptr() as *const libc::c_char,
                            path_buf.as_mut_ptr() as *mut libc::c_char,
                            path_buf.len() - 1,
                        )
                    };
                    if n > 0 {
                        path_buf.truncate(n as usize);
                        String::from_utf8_lossy(&path_buf).into_owned()
                    } else {
                        "<unknown>".to_string()
                    }
                };

                // 检查是否在 blocklist 中
                let blocked = {
                    let set = self.blocked.lock().unwrap();
                    set.is_blocked(&exec_path)
                };

                if blocked {
                    log::info!("[app-blocker] DENY exec: {exec_path} (pid={ev_pid})");
                    // 先写响应（event_fd 仍有效时），再 close
                    self.respond(ev_fd, FAN_DENY as u32);
                    unsafe { close(ev_fd) };
                    // 发桌面通知（非阻塞）
                    let name = std::path::Path::new(&exec_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&exec_path)
                        .to_string();
                    std::thread::spawn(move || {
                        let _ = std::process::Command::new("notify-send")
                            .args([
                                "--urgency=normal",
                                "--icon=dialog-error",
                                "Antidistractor",
                                &format!("已阻止 \"{name}\" 启动"),
                            ])
                            .status();
                    });
                } else {
                    self.respond(ev_fd, FAN_ALLOW as u32);
                    unsafe { close(ev_fd) };
                }
            }
        }
    }

    /// 向 fanotify fd 写入响应。event_fd 必须仍然有效（close 在此函数调用之后）。
    fn respond(&self, event_fd: i32, response: u32) {
        let resp = FanotifyResponse { fd: event_fd, response };
        let n = unsafe {
            write(
                self.fan_fd,
                &resp as *const _ as *const libc::c_void,
                std::mem::size_of::<FanotifyResponse>(),
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            log::warn!("[app-blocker] respond write error (fd={event_fd} resp={response}): {e}");
        }
    }
}

impl Drop for AppBlocker {
    fn drop(&mut self) {
        unsafe { close(self.fan_fd) };
    }
}
