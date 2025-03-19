use std::process;
use std::ptr;
use std::io::Error;
use std::ffi::CStr;
use std::ffi::c_char;
use libc;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct PollArgs {
    /// Process/Thread ID to dump
    #[arg(short, long)]
    id: u32,

    // Verbose info about file descriptors
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn c_char_ptr_to_string(ptr: *const c_char) -> String {
    unsafe {
	CStr::from_ptr(ptr).to_str().unwrap().to_string()
    }
}

fn strerror(errno:i32) -> String {
    unsafe {
	c_char_ptr_to_string(libc::strerror(errno))
    }
}

fn get_errno() -> libc::c_int {
    Error::last_os_error().raw_os_error().unwrap()
}

fn main() {
    let args = PollArgs::parse();

    let res = unsafe {
	libc::ptrace(libc::PT_ATTACH, args.id as i32, ptr::null_mut(), 0)
    };
    if res == -1 {
	let errno = get_errno();
	eprintln!("Attach to {} failed: {}", args.id, strerror(errno));
	process::exit(1);
    }
    if args.verbose >= 2 {
	eprintln!("Attached to {}", args.id)
    }
    let res = unsafe {
	libc::ptrace(libc::PT_DETACH, args.id as i32, ptr::null_mut(), 0)
    };
    if res == -1 {
	let errno = get_errno();
	eprintln!("Detach from {} failed: {}", args.id, strerror(errno));
	process::exit(1);
    }
    if args.verbose >= 2 {
	eprintln!("Detached from {}", args.id)
    }
    process::exit(0);
}
