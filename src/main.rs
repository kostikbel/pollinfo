
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct PollArgs {
    /// Process ID to dump
    #[arg(short, long)]
    pid: Option<u32>,

    /// Thread ID to dump
    #[arg(short, long)]
    tid: Option<u32>,
}
fn main() {
    println!("Hello, world!");

    let args = PollArgs::parse();
    println!("args pid {:?} tid {:?}", args.pid, args.tid);
}
