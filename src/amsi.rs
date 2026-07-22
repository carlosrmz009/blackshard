//! Bounded access to the Windows Antimalware Scan Interface (AMSI).
//!
//! AMSI is a secondary signal supplied by an antimalware provider already
//! installed on the machine. It is deliberately not treated as a file
//! signature source: a provider detection can stop execution, but it must not
//! by itself authorize destructive actions such as automatic quarantine.

use std::fmt;

/// Maximum number of bytes submitted to an AMSI provider for one scan.
///
/// The primary Blackshard engines retain their own independent limits. This
/// lower ceiling prevents a synchronous third-party provider from receiving an
/// unexpectedly large allocation or doing unbounded work on Blackshard's
/// real-time path.
pub const MAX_AMSI_SAMPLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_APPLICATION_NAME_UTF16_UNITS: usize = 128;
const MAX_CONTENT_NAME_UTF16_UNITS: usize = 1024;

const AMSI_RESULT_CLEAN: u32 = 0;
const AMSI_RESULT_BLOCKED_BY_ADMIN_START: u32 = 0x4000;
const AMSI_RESULT_BLOCKED_BY_ADMIN_END: u32 = 0x4fff;
const AMSI_RESULT_DETECTED: u32 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmsiVerdict {
    Clean,
    NotDetected,
    BlockedByAdministrator,
    MalwareDetected,
}

impl AmsiVerdict {
    fn from_raw(result: u32) -> Self {
        if result >= AMSI_RESULT_DETECTED {
            Self::MalwareDetected
        } else if (AMSI_RESULT_BLOCKED_BY_ADMIN_START..=AMSI_RESULT_BLOCKED_BY_ADMIN_END)
            .contains(&result)
        {
            Self::BlockedByAdministrator
        } else if result == AMSI_RESULT_CLEAN {
            Self::Clean
        } else {
            Self::NotDetected
        }
    }

    pub fn is_provider_detection(self) -> bool {
        self == Self::MalwareDetected
    }

    pub fn should_block_execution(self) -> bool {
        matches!(self, Self::MalwareDetected | Self::BlockedByAdministrator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmsiScanReport {
    pub verdict: AmsiVerdict,
    pub raw_result: u32,
    pub bytes_scanned: usize,
    pub truncated: bool,
}

impl AmsiScanReport {
    fn from_raw(raw_result: u32, bytes_scanned: usize, truncated: bool) -> Self {
        Self {
            verdict: AmsiVerdict::from_raw(raw_result),
            raw_result,
            bytes_scanned,
            truncated,
        }
    }

    pub fn is_provider_detection(&self) -> bool {
        self.verdict.is_provider_detection()
    }

    pub fn should_block_execution(&self) -> bool {
        self.verdict.should_block_execution()
    }

    #[cfg(test)]
    pub(crate) fn synthetic(raw_result: u32, bytes_scanned: usize, truncated: bool) -> Self {
        Self::from_raw(raw_result, bytes_scanned, truncated)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmsiError {
    Unavailable(String),
    InvalidInput(&'static str),
    Windows {
        operation: &'static str,
        hresult: i32,
    },
}

impl AmsiError {
    #[cfg(windows)]
    fn windows(operation: &'static str, hresult: i32) -> Self {
        Self::Windows { operation, hresult }
    }
}

impl fmt::Display for AmsiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "AMSI is unavailable: {message}"),
            Self::InvalidInput(message) => write!(formatter, "invalid AMSI input: {message}"),
            Self::Windows { operation, hresult } => write!(
                formatter,
                "{operation} failed with HRESULT 0x{:08x}",
                *hresult as u32
            ),
        }
    }
}

impl std::error::Error for AmsiError {}

/// A process-local AMSI context. Initialization and teardown are RAII-managed;
/// each call opens its own correlation session and closes it before returning.
pub struct AmsiScanner {
    inner: platform::Scanner,
}

impl AmsiScanner {
    pub fn new(application_name: &str) -> Result<Self, AmsiError> {
        validate_wide_input(
            application_name,
            MAX_APPLICATION_NAME_UTF16_UNITS,
            "the application name is empty, contains NUL, or is too long",
        )?;
        platform::Scanner::new(application_name).map(|inner| Self { inner })
    }

    pub fn scan_buffer(
        &self,
        bytes: &[u8],
        content_name: &str,
    ) -> Result<AmsiScanReport, AmsiError> {
        validate_wide_input(
            content_name,
            MAX_CONTENT_NAME_UTF16_UNITS,
            "the content name is empty, contains NUL, or is too long",
        )?;

        let (sample, truncated) = bounded_sample(bytes);
        if sample.is_empty() {
            return Ok(AmsiScanReport::from_raw(1, 0, false));
        }
        let raw_result = self.inner.scan_buffer(sample, content_name)?;
        Ok(AmsiScanReport::from_raw(
            raw_result,
            sample.len(),
            truncated,
        ))
    }
}

fn validate_wide_input(
    value: &str,
    maximum_utf16_units: usize,
    message: &'static str,
) -> Result<(), AmsiError> {
    if value.is_empty()
        || value.chars().any(|character| character == '\0')
        || value.encode_utf16().count() > maximum_utf16_units
    {
        return Err(AmsiError::InvalidInput(message));
    }
    Ok(())
}

fn bounded_sample(bytes: &[u8]) -> (&[u8], bool) {
    let sample_length = bytes.len().min(MAX_AMSI_SAMPLE_BYTES);
    (&bytes[..sample_length], bytes.len() > sample_length)
}

#[cfg(windows)]
mod platform {
    use super::AmsiError;
    use std::ffi::{c_char, c_void};
    use std::sync::Arc;

    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

    type AmsiInitializeFn = unsafe extern "system" fn(*const u16, *mut usize) -> i32;
    type AmsiUninitializeFn = unsafe extern "system" fn(usize);
    type AmsiOpenSessionFn = unsafe extern "system" fn(usize, *mut usize) -> i32;
    type AmsiCloseSessionFn = unsafe extern "system" fn(usize, usize);
    type AmsiScanBufferFn =
        unsafe extern "system" fn(usize, *const c_void, u32, *const u16, usize, *mut u32) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(file_name: *const u16, file: isize, flags: u32) -> isize;
        fn GetProcAddress(module: isize, procedure_name: *const c_char) -> *const c_void;
        fn FreeLibrary(module: isize) -> i32;
    }

    struct Api {
        module: isize,
        initialize: AmsiInitializeFn,
        uninitialize: AmsiUninitializeFn,
        open_session: AmsiOpenSessionFn,
        close_session: AmsiCloseSessionFn,
        scan_buffer: AmsiScanBufferFn,
    }

    impl Api {
        fn load() -> Result<Self, AmsiError> {
            let dll: Vec<u16> = "amsi.dll".encode_utf16().chain(Some(0)).collect();
            let module = unsafe { LoadLibraryExW(dll.as_ptr(), 0, LOAD_LIBRARY_SEARCH_SYSTEM32) };
            if module == 0 {
                return Err(AmsiError::Unavailable(format!(
                    "could not load the system amsi.dll: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let resolved = unsafe {
                (|| {
                    Ok(Self {
                        module,
                        initialize: resolve(module, b"AmsiInitialize\0")?,
                        uninitialize: resolve(module, b"AmsiUninitialize\0")?,
                        open_session: resolve(module, b"AmsiOpenSession\0")?,
                        close_session: resolve(module, b"AmsiCloseSession\0")?,
                        scan_buffer: resolve(module, b"AmsiScanBuffer\0")?,
                    })
                })()
            };
            if resolved.is_err() {
                unsafe {
                    FreeLibrary(module);
                }
            }
            resolved
        }
    }

    impl Drop for Api {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }

    unsafe fn resolve<T: Copy>(module: isize, name: &'static [u8]) -> Result<T, AmsiError> {
        let address = GetProcAddress(module, name.as_ptr().cast());
        if address.is_null() {
            let symbol = String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]);
            return Err(AmsiError::Unavailable(format!(
                "system amsi.dll does not export {symbol}"
            )));
        }
        Ok(std::mem::transmute_copy(&address))
    }

    struct Context {
        handle: usize,
        api: Arc<Api>,
    }

    impl Drop for Context {
        fn drop(&mut self) {
            unsafe {
                (self.api.uninitialize)(self.handle);
            }
        }
    }

    struct Session<'a> {
        context: &'a Context,
        handle: usize,
    }

    impl Session<'_> {
        fn open(context: &Context) -> Result<Session<'_>, AmsiError> {
            let mut handle = 0usize;
            let result = unsafe { (context.api.open_session)(context.handle, &mut handle) };
            if result < 0 {
                return Err(AmsiError::windows("AmsiOpenSession", result));
            }
            if handle == 0 {
                return Err(AmsiError::Unavailable(
                    "AmsiOpenSession returned a null session".to_owned(),
                ));
            }
            Ok(Session { context, handle })
        }
    }

    impl Drop for Session<'_> {
        fn drop(&mut self) {
            unsafe {
                (self.context.api.close_session)(self.context.handle, self.handle);
            }
        }
    }

    pub(super) struct Scanner {
        context: Arc<Context>,
    }

    impl Scanner {
        pub(super) fn new(application_name: &str) -> Result<Self, AmsiError> {
            let api = Arc::new(Api::load()?);
            let application_name: Vec<u16> =
                application_name.encode_utf16().chain(Some(0)).collect();
            let mut context_handle = 0usize;
            let result =
                unsafe { (api.initialize)(application_name.as_ptr(), &mut context_handle) };
            if result < 0 {
                return Err(AmsiError::windows("AmsiInitialize", result));
            }
            if context_handle == 0 {
                return Err(AmsiError::Unavailable(
                    "AmsiInitialize returned a null context".to_owned(),
                ));
            }
            Ok(Self {
                context: Arc::new(Context {
                    handle: context_handle,
                    api,
                }),
            })
        }

        pub(super) fn scan_buffer(
            &self,
            bytes: &[u8],
            content_name: &str,
        ) -> Result<u32, AmsiError> {
            let context = Arc::clone(&self.context);
            let session = Session::open(&context)?;
            let content_name: Vec<u16> = content_name.encode_utf16().chain(Some(0)).collect();
            let mut result = 0u32;
            let hresult = unsafe {
                (context.api.scan_buffer)(
                    context.handle,
                    bytes.as_ptr().cast(),
                    bytes.len() as u32,
                    content_name.as_ptr(),
                    session.handle,
                    &mut result,
                )
            };
            if hresult < 0 {
                return Err(AmsiError::windows("AmsiScanBuffer", hresult));
            }
            drop(session);
            Ok(result)
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::AmsiError;

    pub(super) struct Scanner;

    impl Scanner {
        pub(super) fn new(_application_name: &str) -> Result<Self, AmsiError> {
            Err(AmsiError::Unavailable(
                "this operating system does not provide amsi.dll".to_owned(),
            ))
        }

        pub(super) fn scan_buffer(
            &self,
            _bytes: &[u8],
            _content_name: &str,
        ) -> Result<u32, AmsiError> {
            Err(AmsiError::Unavailable(
                "this operating system does not provide amsi.dll".to_owned(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amsi_result_ranges_are_mapped_without_guessing() {
        assert_eq!(AmsiVerdict::from_raw(0), AmsiVerdict::Clean);
        assert_eq!(AmsiVerdict::from_raw(1), AmsiVerdict::NotDetected);
        assert_eq!(
            AmsiVerdict::from_raw(AMSI_RESULT_BLOCKED_BY_ADMIN_START),
            AmsiVerdict::BlockedByAdministrator
        );
        assert_eq!(
            AmsiVerdict::from_raw(AMSI_RESULT_BLOCKED_BY_ADMIN_END),
            AmsiVerdict::BlockedByAdministrator
        );
        assert_eq!(
            AmsiVerdict::from_raw(AMSI_RESULT_DETECTED),
            AmsiVerdict::MalwareDetected
        );
        assert_eq!(
            AmsiVerdict::from_raw(u32::MAX),
            AmsiVerdict::MalwareDetected
        );
    }

    #[test]
    fn only_provider_and_administrator_detections_block_execution() {
        assert!(!AmsiVerdict::Clean.should_block_execution());
        assert!(!AmsiVerdict::NotDetected.should_block_execution());
        assert!(AmsiVerdict::BlockedByAdministrator.should_block_execution());
        assert!(AmsiVerdict::MalwareDetected.should_block_execution());
        assert!(!AmsiVerdict::BlockedByAdministrator.is_provider_detection());
        assert!(AmsiVerdict::MalwareDetected.is_provider_detection());
    }

    #[test]
    fn provider_sample_is_strictly_bounded() {
        let bytes = vec![0u8; MAX_AMSI_SAMPLE_BYTES + 17];
        let (sample, truncated) = bounded_sample(&bytes);
        assert_eq!(sample.len(), MAX_AMSI_SAMPLE_BYTES);
        assert!(truncated);
    }

    #[test]
    fn names_are_bounded_and_reject_interior_nul() {
        assert!(validate_wide_input("Blackshard", 128, "invalid").is_ok());
        assert!(validate_wide_input("bad\0name", 128, "invalid").is_err());
        assert!(validate_wide_input(&"a".repeat(129), 128, "invalid").is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_backend_is_an_explicit_unavailable_error() {
        assert!(matches!(
            AmsiScanner::new("Blackshard"),
            Err(AmsiError::Unavailable(_))
        ));
    }
}
