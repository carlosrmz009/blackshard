use std::mem;

const MAX_FILE_PATH_LENGTH: usize = 1024;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FilterMessageHeader {
    reply_length: u32,
    message_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BlackshardNotification {
    magic: u32,
    version: u16,
    size: u16,
    process_id: u32,
    desired_access: u32,
    operation: u32,
    path_length: u32,
    file_path: [u16; MAX_FILE_PATH_LENGTH],
    file_id: u64,
    content_generation: u64,
    process_start_key: u64,
    must_enforce: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BlackshardMessage {
    header: FilterMessageHeader,
    notification: BlackshardNotification,
}

fn main() {
    println!(
        "BlackshardNotification size: {}",
        mem::size_of::<BlackshardNotification>()
    );
    println!(
        "FilterMessageHeader size: {}",
        mem::size_of::<FilterMessageHeader>()
    );
    println!(
        "BlackshardMessage size: {}",
        mem::size_of::<BlackshardMessage>()
    );
    println!(
        "BlackshardMessage alignment: {}",
        mem::align_of::<BlackshardMessage>()
    );
}
