use clap::Parser;
use std::ffi::CStr;
use std::ffi::c_char;
use std::io::Error;
use std::process;
use std::ptr;

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
    unsafe { CStr::from_ptr(ptr).to_str().unwrap().to_string() }
}

fn strerror(errno: i32) -> String {
    unsafe { c_char_ptr_to_string(libc::strerror(errno)) }
}

fn get_errno() -> libc::c_int {
    Error::last_os_error().raw_os_error().unwrap()
}

macro_rules! call_ptrace {
    ($ptrace_op:expr, $args:expr, $addr:expr, $data:expr,
     $err_fmt:expr, $ok_fmt:expr, $($x:expr,)* ) => {
        let res = unsafe {
	    libc::ptrace($ptrace_op, $args.id as i32, $addr as *mut i8,
			 $data as i32)
	};
        if res == -1 {
            let errno = get_errno();
            eprintln!($err_fmt, strerror(errno));
            process::exit(1);
        }
        if $args.verbose >= 2 {
            eprintln!($ok_fmt, $($x,)*);
        }
    };
}

fn handle_poll(lwpi: &libc::ptrace_lwpinfo, args: &PollArgs) {
    let nargs = lwpi.pl_syscall_narg as usize;
    let mut scargs = vec![0; nargs];
    let scargs_raw = scargs.as_mut_ptr();
    call_ptrace!(
        libc::PT_GET_SC_ARGS, args, scargs_raw, 0,
        "Fetching poll args failed: {}",
        "Fetched poll args pfds[] {} nfds {}", scargs[0], scargs[1],
    );

    let nfds = scargs[1] as usize;
    let mut pfds = vec![libc::pollfd { fd: 0, events: 0, revents: 0,}; nfds];
    let pfds_raw = pfds.as_mut_ptr();
    let mut pt_io_desc = libc::ptrace_io_desc {
        piod_op: libc::PIOD_READ_D,
        piod_offs: scargs[0] as *mut libc::c_void,
        piod_addr: pfds_raw as *mut libc::c_void,
        piod_len: nfds * std::mem::size_of::<libc::pollfd>(),
    };
    call_ptrace!(
	libc::PT_IO, args, &raw mut pt_io_desc, 0,
	"Fetching pollfd array failed: {}",
	"Fetched pollfd array",
    );

    println!("lwp id {} polling on:", lwpi.pl_lwpid);
    pfds.iter().filter(|pfd| pfd.fd >= 0).for_each({
        |pfd| {
            println!("{}", pfd.fd);
        }
    });
}

fn main() {
    let args = PollArgs::parse();

    call_ptrace!(
	libc::PT_ATTACH, args, ptr::null_mut(), 0,
        "Attach failed: {}",
        "Attached to {}", args.id,
    );

    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let res = unsafe {
	libc::waitid(libc::P_PID, args.id as libc::id_t,
		     &mut si, libc::WUNTRACED)
    };
    if res == -1 {
        let errno = get_errno();
        eprintln!("Wait for initial stop failed: {}", strerror(errno));
        process::exit(1);
    }
    if args.verbose >= 2 {
        eprintln!("Consumed initial stop event");
    }

    let mut lwpi: libc::ptrace_lwpinfo = unsafe { std::mem::zeroed() };
    call_ptrace!(
        libc::PT_LWPINFO, args, &raw mut lwpi,
        std::mem::size_of::<libc::ptrace_lwpinfo>(),
        "Fetching lwpinfo failed: {}",
        "Fetched lwpinfo event {} flags {:#x} syscall {} nargs {}",
        lwpi.pl_event, lwpi.pl_flags, lwpi.pl_syscall_code,
	lwpi.pl_syscall_narg,
    );

    if lwpi.pl_syscall_code == 209 /* poll */ ||
	lwpi.pl_syscall_code == 545 /* ppoll */ {
            handle_poll(&lwpi, &args)
    }

    call_ptrace!(
	libc::PT_DETACH, args, ptr::null_mut(), 0,
        "Detach failed: {}",
        "Detached from {}", args.id,
    );
    process::exit(0);
}
