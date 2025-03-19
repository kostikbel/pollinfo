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
fn main() {
    let args = PollArgs::parse();
    println!("args id {} verbose {:?}", args.id, args.verbose);
}
