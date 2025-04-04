/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>
 * under sponsorship from the FreeBSD Foundation.
 */

#![allow(path_statements)]

use clap::Parser;
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::c_char;
use std::io;
use std::io::Error;
use std::io::Write;
use std::process;
use std::process::Command;
use std::process::Output;
use std::ptr;
use std::str;

#[derive(Parser, Debug)]
#[command(version,
	  about = "Dump file descriptors causing poll/select to wait",
	  long_about = None)]
struct PollArgs {
    /// Process ID to dump
    #[arg(short, long)]
    id: u32,

    /// Once for verbose info about file descriptors, twice for debug traces
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

struct Context {
    id: u32,
    verbose: u8,
    attached: bool,
    fd_info: HashMap<usize, String>,
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

fn cstring_to_string(bytes: &[libc::c_char]) -> String {
    unsafe { std::str::from_utf8_unchecked(std::mem::transmute(bytes)) }.
	to_string()
}

macro_rules! call_ptrace {
    ($ptrace_op:expr, $ctx:expr, $lwpid:expr, $addr:expr, $data:expr,
     $err_fmt:expr, $ok_fmt:expr, $($x:expr,)* ) => {{
        let res = unsafe {
	    libc::ptrace($ptrace_op, $lwpid as i32, $addr as *mut i8,
			 $data as i32)
	};
        if res == -1 {
            let errno = get_errno();
            eprintln!($err_fmt, strerror(errno));
	    terminate($ctx, 1);
        }
        if $ctx.verbose >= 2 {
            eprintln!($ok_fmt, $($x,)*);
        }
	res
     }}
}

fn terminate(ctx: &Context, ecode: i32) {
    if ctx.attached {
	call_ptrace!(
	    libc::PT_DETACH, &ctx, ctx.id, ptr::null_mut(), 0,
            "Detach failed: {}",
            "Detached from {}", ctx.id,
	);
    }
    process::exit(ecode)
}

fn handle_poll(lwpi: &libc::ptrace_lwpinfo, ctx: &Context) {
    let nargs = lwpi.pl_syscall_narg as usize;
    if nargs < 3 {
	eprintln!("poll-like syscall no {} with {} args",
		  lwpi.pl_syscall_code, nargs);
	return;
    }
    let mut scargs = vec![0; nargs];
    let scargs_raw = scargs.as_mut_ptr();
    call_ptrace!(
        libc::PT_GET_SC_ARGS, ctx, lwpi.pl_lwpid, scargs_raw,
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
	    libc::PT_IO, ctx, lwpi.pl_lwpid, &raw mut pt_io_desc, 0,
	    "Fetching pollfd array failed: {}",
	    "Fetched pollfd array",
	);
    }

    println!("lwp id {} ({}) polling on:", lwpi.pl_lwpid,
	     cstring_to_string(&lwpi.pl_tdname));
    pfds.iter().filter(|pfd| pfd.fd >= 0).for_each({|pfd| {
	let instr = if (pfd.events & (libc::POLLIN | libc::POLLRDNORM |
	    libc::POLLRDBAND | libc::POLLPRI)) != 0 { "r" } else { " "};
	let outstr = if (pfd.events & (libc::POLLOUT | libc::POLLWRNORM |
	    libc::POLLWRBAND)) != 0 { "w" } else { " "};
	let exstr = "e"; /* POLERR is always checked */
        print!("{:8} {}{}{}", pfd.fd, instr, outstr, exstr);
	if ctx.verbose >= 1 {
	    let fd = pfd.fd as usize;
	    let info = match ctx.fd_info.get(&fd) {
		Some(v) => v,
		None => "",
	    };
	    print!(" {}", info);
	}
	println!("");
    }});
}

fn handle_select_fetch_fds(lwpi: &libc::ptrace_lwpinfo, ctx: &Context,
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
	libc::PT_IO, ctx, lwpi.pl_lwpid, &raw mut pt_io_desc, 0,
	"Fetching fds array failed: {}",
	"Fetched {}fds array", name,
    );
}

fn handle_select(lwpi: &libc::ptrace_lwpinfo, ctx: &Context) {
    let nargs = lwpi.pl_syscall_narg as usize;
    if nargs < 5 {
	eprintln!("select-like syscall no {} with {} args",
		  lwpi.pl_syscall_code, nargs);
	return;
    }
    let mut scargs = vec![0; nargs];
    let scargs_raw = scargs.as_mut_ptr();
    call_ptrace!(
        libc::PT_GET_SC_ARGS, ctx, lwpi.pl_lwpid, scargs_raw,
	nargs * std::mem::size_of::<libc::register_t>(),
        "Fetching select args failed: {}",
        "Fetched select args nfds {} {:#x} {:#x} {:#x}",
	scargs[0], scargs[1], scargs[2], scargs[3],
    );

    println!("lwp id {} ({}) selecting on:", lwpi.pl_lwpid,
	     cstring_to_string(&lwpi.pl_tdname));
    let nfds = scargs[0] as usize;
    if nfds == 0 {
	return;
    }
    let fds_len = nfds.div_ceil(u8::BITS as usize);

    let mut infds = vec![0u8; fds_len];
    handle_select_fetch_fds(lwpi, ctx, &mut infds, fds_len, scargs[1], "in");
    let mut outfds = vec![0u8; fds_len];
    handle_select_fetch_fds(lwpi, ctx, &mut outfds, fds_len, scargs[2], "out");
    let mut exfds = vec![0u8; fds_len];
    handle_select_fetch_fds(lwpi, ctx, &mut exfds, fds_len, scargs[3], "ex");

    for fd in 0..(nfds - 1) {
	let idx = fd / u8::BITS as usize;
	let bit = 1 << (fd % u8::BITS as usize);
	if (infds[idx] | outfds[idx] | exfds[idx]) & bit == 0 {
	    continue;
	}
	let instr = if (infds[idx] & bit) != 0 { "i" } else { " " };
	let outstr = if (outfds[idx] & bit) != 0 { "o" } else { " " };
	let exstr = if (exfds[idx] & bit) != 0 { "e" } else { " "} ;
	print!("{:8} {}{}{}", fd, instr, outstr, exstr);
	if ctx.verbose >= 1 {
	    let info = match ctx.fd_info.get(&fd) {
		Some(v) => v,
		None => "",
	    };
	    print!(" {}", info);
	}
	println!("");
    }
}

fn handle_lwp(ctx: &Context, lwpid: libc::lwpid_t) {
    let mut lwpi: libc::ptrace_lwpinfo = unsafe { std::mem::zeroed() };
    call_ptrace!(
        libc::PT_LWPINFO, ctx, lwpid, &raw mut lwpi,
        std::mem::size_of::<libc::ptrace_lwpinfo>(),
        "Fetching lwpinfo failed: {}",
        "Fetched lwpinfo lwpid {} event {} flags {:#x} syscall {} nargs {}",
        lwpi.pl_lwpid, lwpi.pl_event, lwpi.pl_flags, lwpi.pl_syscall_code,
	lwpi.pl_syscall_narg,
    );

    if lwpi.pl_syscall_code == 209 /* poll */ ||
	lwpi.pl_syscall_code == 545 /* ppoll */ {
            handle_poll(&lwpi, ctx)
    } else if lwpi.pl_syscall_code == 93 /* select */ ||
	lwpi.pl_syscall_code == 522 /* pselect */ {
            handle_select(&lwpi, ctx)
    }
}

fn parse_procstat(ctx: &mut Context, procstat: &str) {
    if ctx.verbose >= 2 {
	eprintln!("Parsing procstat files {} output", ctx.id);
    }
    procstat.lines().skip(1).for_each(|line| {
	let mut fields = line.split(char::is_whitespace)
	    .filter(|str| { str.len() > 0 });
	let _pid = fields.next();
	let _comm = fields.next();
	let fd_str = match fields.next() {
	    Some(fd_strx) => {
		if fd_strx.len() != 0 { fd_strx } else { "" }
	    },
	    None => { return },
	};
	let fd = match usize::from_str_radix(fd_str, 10) {
	    Ok(res) => res,
	    Err(_) => { return },
	};
	let mut info_str = "".to_string();
	fields.for_each(|f| {
	    info_str.push_str(" ");
	    info_str.push_str(f); }
	);
	if ctx.verbose >= 2 {
	    eprintln!("fd {} info {}", fd, info_str);
	}
	ctx.fd_info.insert(fd, info_str.to_string());
    });
}

fn call_procstat(ctx: &mut Context) {
    let procstat_result = Command::new("procstat")
	.arg("files")
	.arg(ctx.id.to_string())
	.output();

    match procstat_result {
	Err(error) => {
	    eprintln!("Execution of procstat failed, error {}", error);
	    terminate(&ctx, 1);
	}
	Ok(Output{status: procstat_status, stdout: procstat_stdout,
		  stderr: procstat_stderr}) => {
	    if ctx.verbose >= 2 {
		eprintln!("Executing procstat files {}", ctx.id);
	    }
	    if procstat_status.success() {
		let procstat_str = match str::from_utf8(
		    procstat_stdout.as_slice()) {
		    Ok(v) => v,
		    Err(e) => {
			eprintln!("Invalid UTF-8 sequence from procstat: {}", e);
			terminate(&ctx, 1);
			""
		    }
		};
		parse_procstat(ctx, &procstat_str)
	    } else {
		match procstat_status.code() {
		    None => {
			eprintln!("procstat terminated by signal")
		    }
		    Some(exit_code) => {
			eprintln!("procstat exited with code {}", exit_code);
		    }
		}
		eprintln!("procstat error:");
		let _ = io::stderr().write(procstat_stderr.as_slice());
		terminate(&ctx, 1);
	    }
	}
    }
}

fn main() {
    let args = PollArgs::parse();
    let mut ctx = Context {
	id: args.id,
	verbose: args.verbose,
	attached: false,
	fd_info: HashMap::new(),
    };

    call_ptrace!(
	libc::PT_ATTACH, &ctx, ctx.id, ptr::null_mut(), 0,
        "Attach failed: {}",
        "Attached to {}", ctx.id,
    );

    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let res = unsafe {
	libc::waitid(libc::P_PID, ctx.id as libc::id_t,
		     &mut si, libc::WUNTRACED)
    };
    if res == -1 {
        let errno = get_errno();
        eprintln!("Wait for initial stop failed: {}", strerror(errno));
        process::exit(1);
    }
    if ctx.verbose >= 2 {
        eprintln!("Consumed initial stop event");
    }

    ctx.attached = true;

    if ctx.verbose >= 1 {
	call_procstat(&mut ctx);
    }

    let nlwps: usize = call_ptrace!(
	libc::PT_GETNUMLWPS, &ctx, ctx.id, ptr::null_mut(), 0,
	"Querying the number of lwps failed: {}",
	"Fetched number of lwps for process {}", ctx.id,) as usize;
    if ctx.verbose >= 2 {
	eprintln!("Process {} executes {} lwps", ctx.id, nlwps);
    }
    let mut lwpids = vec![0; nlwps];
    let lwpids_raw = lwpids.as_mut_ptr();
    call_ptrace!(
	libc::PT_GETLWPLIST, &ctx, ctx.id, lwpids_raw,
	nlwps * std::mem::size_of::<libc::lwpid_t>(),
	"Fetching list of lwpids failed: {}",
	"Fetched list of lwpids for process {}", ctx.id,
    );
    lwpids.iter().for_each(|lwpid| {
	handle_lwp(&ctx, *lwpid)
    });

    terminate(&ctx, 0);
}
