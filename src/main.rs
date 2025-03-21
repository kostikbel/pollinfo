#![allow(path_statements)]

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
    ($ptrace_op:expr, $args:expr, $lwpid:expr, $addr:expr, $data:expr,
     $err_fmt:expr, $ok_fmt:expr, $($x:expr,)* ) => {{
        let res = unsafe {
	    libc::ptrace($ptrace_op, $lwpid as i32, $addr as *mut i8,
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
	res
     }}
}

fn handle_poll(lwpi: &libc::ptrace_lwpinfo, args: &PollArgs) {
    let nargs = lwpi.pl_syscall_narg as usize;
    if nargs < 3 {
	eprintln!("poll-like syscall no {} with {} args",
		  lwpi.pl_syscall_code, nargs);
	return;
    }
    let mut scargs = vec![0; nargs];
    let scargs_raw = scargs.as_mut_ptr();
    call_ptrace!(
        libc::PT_GET_SC_ARGS, args, args.id, scargs_raw,
	nargs * std::mem::size_of::<libc::register_t>(),
        "Fetching poll args failed: {}",
        "Fetched poll args pfds[] {} nfds {}", scargs[0], scargs[1],
    );

    let nfds = scargs[1] as usize;
    let mut pfds = vec![libc::pollfd { fd: 0, events: 0, revents: 0,}; nfds];
    if nfds > 0 && scargs[0] != 0 {
	let pfds_raw = pfds.as_mut_ptr();
	let mut pt_io_desc = libc::ptrace_io_desc {
            piod_op: libc::PIOD_READ_D,
            piod_offs: scargs[0] as *mut libc::c_void,
            piod_addr: pfds_raw as *mut libc::c_void,
            piod_len: nfds * std::mem::size_of::<libc::pollfd>(),
	};
	call_ptrace!(
	    libc::PT_IO, args, args.id, &raw mut pt_io_desc, 0,
	    "Fetching pollfd array failed: {}",
	    "Fetched pollfd array",
	);
    }

    println!("lwp id {} polling on:", lwpi.pl_lwpid);
    pfds.iter().filter(|pfd| pfd.fd >= 0).for_each({|pfd| {
	let instr = if (pfd.events & (libc::POLLIN | libc::POLLRDNORM |
	    libc::POLLRDBAND | libc::POLLPRI)) != 0 { "r" } else { " "};
	let outstr = if (pfd.events & (libc::POLLOUT | libc::POLLWRNORM |
	    libc::POLLWRBAND)) != 0 { "w" } else { " "};
	let exstr = "e"; /* POLERR is always checked */
        println!("{:8} {}{}{}", pfd.fd, instr, outstr, exstr);
    }});
}

fn handle_select_fetch_fds(lwpi: &libc::ptrace_lwpinfo, args: &PollArgs,
fds: &mut Vec<u8>, fds_len: usize, off: libc::register_t, name: &str) {
    if off == 0 {
	return;
    }
    let fds_raw = fds.as_mut_ptr();
    let mut pt_io_desc = libc::ptrace_io_desc {
        piod_op: libc::PIOD_READ_D,
        piod_offs: off as *mut libc::c_void,
        piod_addr: fds_raw as *mut libc::c_void,
        piod_len: fds_len,
    };
    call_ptrace!(
	libc::PT_IO, args, lwpi.pl_lwpid, &raw mut pt_io_desc, 0,
	"Fetching fds array failed: {}",
	"Fetched {}fds array", name,
    );
}

fn handle_select(lwpi: &libc::ptrace_lwpinfo, args: &PollArgs) {
    let nargs = lwpi.pl_syscall_narg as usize;
    if nargs < 5 {
	eprintln!("select-like syscall no {} with {} args",
		  lwpi.pl_syscall_code, nargs);
	return;
    }
    let mut scargs = vec![0; nargs];
    let scargs_raw = scargs.as_mut_ptr();
    call_ptrace!(
        libc::PT_GET_SC_ARGS, args, lwpi.pl_lwpid, scargs_raw,
	nargs * std::mem::size_of::<libc::register_t>(),
        "Fetching select args failed: {}",
        "Fetched select args nfds {} {:#x} {:#x} {:#x}",
	scargs[0], scargs[1], scargs[2], scargs[3],
    );

    println!("lwp id {} selecting on:", lwpi.pl_lwpid);
    let nfds = scargs[0] as usize;
    if nfds == 0 {
	return;
    }
    let fds_len = nfds.div_ceil(u8::BITS as usize);

    let mut infds = vec![0u8; fds_len];
    handle_select_fetch_fds(lwpi, args, &mut infds, fds_len, scargs[1], "in");
    let mut outfds = vec![0u8; fds_len];
    handle_select_fetch_fds(lwpi, args, &mut outfds, fds_len, scargs[2], "out");
    let mut exfds = vec![0u8; fds_len];
    handle_select_fetch_fds(lwpi, args, &mut exfds, fds_len, scargs[3], "ex");

    for fd in 0..(nfds - 1) {
	let idx = fd / u8::BITS as usize;
	let bit = 1 << (fd % u8::BITS as usize);
	if (infds[idx] | outfds[idx] | exfds[idx]) & bit == 0 {
	    continue;
	}
	let instr = if (infds[idx] & bit) != 0 { "i" } else { " " };
	let outstr = if (outfds[idx] & bit) != 0 { "o" } else { " " };
	let exstr = if (exfds[idx] & bit) != 0 { "e" } else { " "} ;
	println!("{:8} {}{}{}", fd, instr, outstr, exstr)
    }
}

fn handle_lwp(args: &PollArgs, lwpid: libc::lwpid_t) {
    let mut lwpi: libc::ptrace_lwpinfo = unsafe { std::mem::zeroed() };
    call_ptrace!(
        libc::PT_LWPINFO, args, lwpid, &raw mut lwpi,
        std::mem::size_of::<libc::ptrace_lwpinfo>(),
        "Fetching lwpinfo failed: {}",
        "Fetched lwpinfo lwpid {} event {} flags {:#x} syscall {} nargs {}",
        lwpi.pl_lwpid, lwpi.pl_event, lwpi.pl_flags, lwpi.pl_syscall_code,
	lwpi.pl_syscall_narg,
    );

    if lwpi.pl_syscall_code == 209 /* poll */ ||
	lwpi.pl_syscall_code == 545 /* ppoll */ {
            handle_poll(&lwpi, &args)
    } else if lwpi.pl_syscall_code == 93 /* select */ ||
	lwpi.pl_syscall_code == 522 /* pselect */ {
            handle_select(&lwpi, &args)
    }
}

fn main() {
    let args = PollArgs::parse();

    call_ptrace!(
	libc::PT_ATTACH, args, args.id, ptr::null_mut(), 0,
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

    let nlwps: usize = call_ptrace!(
	libc::PT_GETNUMLWPS, args, args.id, ptr::null_mut(), 0,
	"Querying the number of lwps failed: {}",
	"Fetched number of lwps for process {}", args.id,) as usize;
    if args.verbose >= 2 {
	eprintln!("Process {} executes {} lwps", args.id, nlwps);
    }
    let mut lwpids = vec![0; nlwps];
    let lwpids_raw = lwpids.as_mut_ptr();
    call_ptrace!(
	libc::PT_GETLWPLIST, args, args.id, lwpids_raw,
	nlwps * std::mem::size_of::<libc::lwpid_t>(),
	"Fetching list of lwpids failed: {}",
	"Fetched list of lwpids for process {}", args.id,
    );
    lwpids.iter().for_each(|lwpid| {
	handle_lwp(&args, *lwpid)
    });

    call_ptrace!(
	libc::PT_DETACH, args, args.id, ptr::null_mut(), 0,
        "Detach failed: {}",
        "Detached from {}", args.id,
    );
    process::exit(0);
}
