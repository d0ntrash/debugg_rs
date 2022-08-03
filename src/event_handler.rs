use windows_sys::Win32::System::Diagnostics::Debug::{DEBUG_EVENT,
                                                     Wow64GetThreadContext,
                                                     WOW64_CONTEXT};
use std::mem;
use std::io::Error;

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
    let rip = thread_context.Eip;
    println!("RIP: {rip}");

}

pub fn exit_thread_debug_handler(debug_event: &DEBUG_EVENT) {
    println!("EXIT_THREAD_DEBUG_EVENT");
    let thread_id = debug_event.dwThreadId;
    println!("EXIT THREAD WITH ID: {thread_id}");
}
