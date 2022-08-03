use windows_sys::Win32::System::Diagnostics::Debug::{DEBUG_EVENT,
                                                     Wow64GetThreadContext,
                                                     WOW64_CONTEXT};
use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};
use std::mem;
use std::io::Error;
use std::char::{decode_utf16, REPLACEMENT_CHARACTER};

pub fn load_dll_debug_event_handler(debug_event: &DEBUG_EVENT) {
    println!("LOAD_DLL_DEBUG_EVENT");
    let dll_event_info = unsafe { debug_event.u.LoadDll };
    let dll_file_handle = dll_event_info.hFile;
    // let dll_base_address = dll_event_info.lpBaseOfDll;
    let mut file_path_buffer: Vec<u16> = vec![0; 255];

    let path_status = unsafe{GetFinalPathNameByHandleW(dll_file_handle,
                                                       file_path_buffer.as_mut_ptr(),
                                                       254,
                                                       FILE_NAME_NORMALIZED)};

    if path_status == 0 {
        let os_error = Error::last_os_error();
        println!("Failed getting thread context: {os_error:?}");
        return;
    }

    let file_path = decode_utf16(file_path_buffer)
        .map(|r| r.unwrap_or(REPLACEMENT_CHARACTER))
        .collect::<String>();
    println!("LOADED DLL FROM: {file_path}");
}

pub fn unload_dll_debug_event_handler(_debug_event: &DEBUG_EVENT) {
    println!("UNLOAD_DLL_DEBUG_EVENT");
}

pub fn create_process_debug_event_handler(debug_event: &DEBUG_EVENT) {
    println!("CREATE_PROCESS_DEBUG_EVENT");
    let pid = debug_event.dwProcessId;
    println!("PID: {pid}");
    let target_process_info = unsafe { debug_event.u.CreateProcessInfo };
    let process_image_base = target_process_info.lpBaseOfImage as usize;
    let process_start_address: usize = unsafe { mem::transmute(target_process_info.lpStartAddress) };
    println!("Image Base: 0x{process_image_base:x}\nEntry point: 0x{process_start_address:x}");
}

pub fn exit_process_debug_event_handler(debug_event: &DEBUG_EVENT) {
    println!("EXIT_PROCESS_DEBUG_EVENT");
    let exit_code = unsafe { debug_event.u.ExitProcess.dwExitCode };
    println!("Process exited with exit code: {exit_code}");
}

pub fn create_thread_debug_handler(debug_event: &DEBUG_EVENT) {
    println!("CREATE_THREAD_DEBUG_EVENT");
    let thread_id = debug_event.dwThreadId;
    let thread_handle = unsafe { debug_event.u.CreateThread.hThread };
    let thread_context = mem::MaybeUninit::<WOW64_CONTEXT>::zeroed();
    let mut thread_context = unsafe { thread_context.assume_init() };
    println!("CREATE THREAD WITH ID: {thread_id}");
    if unsafe { Wow64GetThreadContext(thread_handle, &mut thread_context) } == 0 {
        let os_error = Error::last_os_error();
        println!("Failed getting thread context: {os_error:?}");
        return;
    }
    let eip = thread_context.Eip;
    println!("EIP: {eip}");

}

pub fn exit_thread_debug_handler(debug_event: &DEBUG_EVENT) {
    println!("EXIT_THREAD_DEBUG_EVENT");

    let thread_id = debug_event.dwThreadId;
    println!("EXIT THREAD WITH ID: {thread_id}");
}
