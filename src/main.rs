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

fn handle_poll(lwpi: &libc::ptrace_lwpinfo, args: &PollArgs) {
    let nargs = lwpi.pl_syscall_narg as usize;
    let mut scargs = Vec::<libc::register_t>::with_capacity(nargs);
    scargs.resize(nargs, 0);
    let scargs_raw = scargs.as_mut_ptr();
    let res = unsafe {
	libc::ptrace(libc::PT_GET_SC_ARGS, args.id as i32,
		     scargs_raw as *mut i8, 0)
    };
    if res == -1 {
	let errno = get_errno();
	eprintln!("Fetching poll args failed: {}", strerror(errno));
	process::exit(1);
    }
    if args.verbose >= 2 {
	eprintln!("Fetched poll args pfds[] {} nfds {}",
		  scargs[0], scargs[1]);
    }

    let nfds = scargs[1] as usize;
    let mut pfds = Vec::<libc::pollfd>::with_capacity(nfds);
    pfds.resize(nfds, libc::pollfd { fd: 0, events: 0, revents: 0 });
    let pfds_raw = pfds.as_mut_ptr();
    let mut pt_io_desc = libc::ptrace_io_desc {
	piod_op: libc::PIOD_READ_D,
	piod_offs: unsafe { std::mem::transmute(scargs[0]) },
	piod_addr: pfds_raw as *mut libc::c_void,
	piod_len: nfds * std::mem::size_of::<libc::pollfd>(),
    };
    let res = unsafe {
	libc::ptrace(libc::PT_IO, args.id as i32,
		     &raw mut pt_io_desc as *mut i8, 0)
    };
    if res == -1 {
	let errno = get_errno();
	eprintln!("Fetching pollfd array failed: {}", strerror(errno));
	process::exit(1);
    }
    if args.verbose >= 2 {
	eprintln!("Fetched pollfd array");
    }

    println!("lwp id {} polling on:", lwpi.pl_lwpid);
    pfds.iter().filter(|pfd| { pfd.fd >= 0 }).for_each({|pfd| {
	println!("{}", pfd.fd);
      }
    });
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

    let mut si: libc::siginfo_t = unsafe {
	std::mem::zeroed()
    };
    let res = unsafe {
	libc::waitid(libc::P_PID, args.id as libc::id_t, &mut si,
		     libc::WUNTRACED)
    };
    if res == -1 {
	let errno = get_errno();
	eprintln!("Wait for initial stop failed: {}", strerror(errno));
	process::exit(1);
    }
    if args.verbose >= 2 {
	eprintln!("Consumed initial stop event");
    }

    let mut lwpi: libc::ptrace_lwpinfo = unsafe {
	std::mem::zeroed()
    };
    let res = unsafe {
	libc::ptrace(libc::PT_LWPINFO, args.id as i32, &raw mut lwpi as *mut i8,
		     std::mem::size_of::<libc::ptrace_lwpinfo>() as i32)
    };
    if res == -1 {
	let errno = get_errno();
	eprintln!("Fetching lwpinfo failed: {}", strerror(errno));
	process::exit(1);
    }
    if args.verbose >= 2 {
	eprintln!("Fetched lwpinfo event {} flags {:#x} syscall {} nargs {}",
		  lwpi.pl_event, lwpi.pl_flags,
		  lwpi.pl_syscall_code, lwpi.pl_syscall_narg);
    }

    if lwpi.pl_syscall_code == 209 /* poll */ ||
	lwpi.pl_syscall_code == 545 /* ppoll */ {
	    handle_poll(&lwpi, &args)
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
