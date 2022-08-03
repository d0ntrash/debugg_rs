use windows_sys::Win32::System::Threading::{STARTUPINFOW, PROCESS_INFORMATION, CreateProcessW, DEBUG_PROCESS};
use windows_sys::Win32::System::Diagnostics::Debug::{DEBUG_EVENT,
                                                     WaitForDebugEvent,
                                                     ContinueDebugEvent,
                                                     CREATE_PROCESS_DEBUG_EVENT,
                                                     EXIT_PROCESS_DEBUG_EVENT,
                                                     CREATE_THREAD_DEBUG_EVENT,
                                                     EXIT_THREAD_DEBUG_EVENT,
                                                     LOAD_DLL_DEBUG_EVENT,
                                                     UNLOAD_DLL_DEBUG_EVENT,
                                                     ADDRESS64};
use windows_sys::Win32::Foundation::DBG_CONTINUE;
use std::ptr;
use std::mem;
use std::io::Error;

mod event_handler;

// https://github.com/headcrab-rs/headcrab/blob/master/src/target/windows.rs
macro_rules! wide_string {
    ($string:expr) => {{
        use std::os::windows::ffi::OsStrExt;
        let input = std::ffi::OsStr::new($string);
        let vec: Vec<u16> = input.encode_wide().chain(Some(0)).collect();
        vec
    }};
}

// fn to_addr64(pointer: u32) -> ADDRESS64 {
//     ADDRESS64 {
//         Offset: pointer as u64,
//         Segment: 0,
//         Mode: 3
//     }
// }

fn main() {
    let startup_info = mem::MaybeUninit::<STARTUPINFOW>::zeroed();
    let startup_info = unsafe { startup_info.assume_init() };
    let process_information = mem::MaybeUninit::<PROCESS_INFORMATION>::zeroed();
    let mut process_information = unsafe { process_information.assume_init() };
    let proc_status: i32 = unsafe {
        CreateProcessW(ptr::null_mut(),
                       wide_string!(&"target.exe").as_mut_ptr(),
                       ptr::null_mut(),
                       ptr::null_mut(),
                       0,
                       DEBUG_PROCESS,
                       ptr::null_mut(),
                       ptr::null_mut(),
                       &startup_info,
                       &mut process_information)
    };
    if proc_status == 0 {
        let os_error = Error::last_os_error();
        println!("Failed creating process: {os_error:?}");
    }
    let pid = process_information.dwProcessId;
    println!("Process created with PID: {pid}");

    let debug_event = mem::MaybeUninit::<DEBUG_EVENT>::zeroed();
    let mut debug_event = unsafe { debug_event.assume_init() };

    loop {
        unsafe{
            if WaitForDebugEvent(&mut debug_event, 100) == 0 {
                continue;
            }
        }

        match debug_event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => event_handler::create_process_debug_event_handler(&debug_event),
            EXIT_PROCESS_DEBUG_EVENT => event_handler::exit_process_debug_event_handler(&debug_event),
            CREATE_THREAD_DEBUG_EVENT => event_handler::create_thread_debug_handler(&debug_event),
            EXIT_THREAD_DEBUG_EVENT => event_handler::exit_thread_debug_handler(&debug_event),
            LOAD_DLL_DEBUG_EVENT => event_handler::load_dll_debug_event_handler(&debug_event),
            UNLOAD_DLL_DEBUG_EVENT => event_handler::unload_dll_debug_event_handler(&debug_event),
            _ => {}
        };
        unsafe {
            ContinueDebugEvent(debug_event.dwProcessId,
                               debug_event.dwThreadId,
                               DBG_CONTINUE as u32)
        };
    }
}
