use windows::core::*;
use windows::Win32::System::Antimalware::*;
use windows::Win32::System::Com::*;
use windows::Win32::Foundation::*;
use std::ffi::c_void;

use blackshard::ipc::{IpcClient, DetectionVerdictView};

const AMSI_PROVIDER_CLSID: GUID = GUID::from_u128(0x00000000_0000_0000_0000_000000000000); // Dummy for now unless a specific one is required. Wait, we can generate a random one.
const MY_CLSID: GUID = GUID::from_u128(0x73a5a75d_bf05_4a2c_8c51_64c1ec8b5c92);

#[implement(IAntimalwareProvider)]
struct BlackshardAmsiProvider;

impl IAntimalwareProvider_Impl for BlackshardAmsiProvider {
    fn Scan(&self, stream: Option<&IAmsiStream>) -> Result<AMSI_RESULT> {
        let stream = match stream {
            Some(s) => s,
            None => return Ok(AMSI_RESULT_CLEAN),
        };

        let mut content = Vec::new();
        let mut buffer = vec![0u8; 8192];
        let mut position = 0u64;
        
        loop {
            let mut read = 0u32;
            unsafe {
                let _ = stream.Read(
                    position,
                    &mut buffer,
                    &mut read,
                );
            }
            if read == 0 {
                break;
            }
            content.extend_from_slice(&buffer[..read as usize]);
            position += read as u64;
            
            // Limit to 4MB just in case
            if content.len() > 4 * 1024 * 1024 {
                break;
            }
        }

        let mut attr_data = vec![0u8; 1024];
        let mut attr_read = 0u32;
        let app_name = match unsafe { stream.GetAttribute(AMSI_ATTRIBUTE_APP_NAME, &mut attr_data, &mut attr_read) } {
            Ok(_) => {
                if attr_read > 0 {
                    let u16_len = attr_read as usize / 2;
                    let u16_slice = unsafe { std::slice::from_raw_parts(attr_data.as_ptr().cast::<u16>(), u16_len) };
                    // Find null terminator if present
                    let len = u16_slice.iter().position(|&c| c == 0).unwrap_or(u16_len);
                    String::from_utf16_lossy(&u16_slice[..len])
                } else {
                    String::from("Unknown")
                }
            }
            Err(_) => String::from("Unknown"),
        };

        let client = IpcClient::default();
        match client.scan_amsi(app_name, content) {
            Ok(DetectionVerdictView::Malicious) => Ok(AMSI_RESULT_DETECTED),
            Ok(DetectionVerdictView::Suspicious) => Ok(AMSI_RESULT_DETECTED), // Or another value?
            Ok(DetectionVerdictView::Clean) => Ok(AMSI_RESULT_CLEAN),
            Ok(DetectionVerdictView::Error) => Ok(AMSI_RESULT_CLEAN),
            Err(_) => Ok(AMSI_RESULT_CLEAN),
        }
    }

    fn CloseSession(&self, _session: u64) {}

    fn DisplayName(&self) -> Result<PWSTR> {
        let name = "Blackshard AMSI Provider\0".encode_utf16().collect::<Vec<_>>();
        unsafe {
            let ptr = CoTaskMemAlloc(name.len() * 2) as *mut u16;
            if ptr.is_null() {
                return Err(windows::core::Error::from(E_OUTOFMEMORY));
            }
            std::ptr::copy_nonoverlapping(name.as_ptr(), ptr, name.len());
            Ok(PWSTR::from_raw(ptr))
        }
    }
}

#[implement(IClassFactory)]
struct ProviderFactory;

impl IClassFactory_Impl for ProviderFactory {
    fn CreateInstance(
        &self,
        outer: Option<&IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> Result<()> {
        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let provider: IAntimalwareProvider = BlackshardAmsiProvider.into();
        unsafe { provider.query(iid, object).ok() }
    }

    fn LockServer(&self, _lock: BOOL) -> Result<()> {
        Ok(())
    }
}

#[no_mangle]
pub extern "system" fn DllGetClassObject(rclsid: *const GUID, riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT {
    unsafe {
        if *rclsid == MY_CLSID {
            let factory: IClassFactory = ProviderFactory.into();
            factory.query(riid, ppv)
        } else {
            CLASS_E_CLASSNOTAVAILABLE
        }
    }
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_OK
}

#[no_mangle]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    S_OK
}

#[no_mangle]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    S_OK
}
