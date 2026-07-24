use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};

pub struct SandboxedChild {
    pub child: Child,
    job_handle: HANDLE,
}

impl Drop for SandboxedChild {
    fn drop(&mut self) {
        if self.job_handle != 0 {
            unsafe {
                CloseHandle(self.job_handle);
            }
        }
    }
}

pub fn spawn_sandboxed_worker() -> std::io::Result<SandboxedChild> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("--parser-worker");
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn()?;
    let job_handle;

    unsafe {
        job_handle = CreateJobObjectW(ptr::null(), ptr::null());
        if job_handle == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut limit_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limit_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY;

        limit_info.BasicLimitInformation.ActiveProcessLimit = 1; // no child processes
        limit_info.ProcessMemoryLimit = 512 * 1024 * 1024; // 512 MB memory limit

        let res = SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            &limit_info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        if res == 0 {
            CloseHandle(job_handle);
            return Err(std::io::Error::last_os_error());
        }

        let proc_handle = child.as_raw_handle() as HANDLE;
        if AssignProcessToJobObject(job_handle, proc_handle) == 0 {
            CloseHandle(job_handle);
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(SandboxedChild {
        child,
        job_handle,
    })
}
