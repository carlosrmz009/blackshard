use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

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

impl SandboxedChild {
    /// Duplicate a service-owned file handle directly into the worker process.
    /// The worker owns and closes the returned handle value.
    pub fn duplicate_handle_into_worker(&self, source: HANDLE) -> std::io::Result<u64> {
        let mut target = 0;
        let succeeded = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                self.child.as_raw_handle() as HANDLE,
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if succeeded == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(target as u64)
        }
    }
}

pub fn spawn_sandboxed_worker() -> std::io::Result<SandboxedChild> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("--clamav-worker");
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

        // The protocol worker may launch exactly one official clamscan child.
        limit_info.BasicLimitInformation.ActiveProcessLimit = 2;
        // Current ClamAV signature generations exceed 512 MiB when compiled.
        // This is a per-process ceiling; the service worker remains tiny while
        // the single resident clamd child may use up to 1536 MiB.
        limit_info.ProcessMemoryLimit = 1536usize * 1024 * 1024;

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

    Ok(SandboxedChild { child, job_handle })
}
