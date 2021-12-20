use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "bridge-v1-node")]
pub struct Opt {
    #[structopt(short = "c", long, parse(from_os_str))]
    pub config: PathBuf,

    #[structopt(short = "n", long)]
    pub network: String,

    #[structopt(short, long)]
    pub transaction_id: Option<String>,

    #[structopt(long)]
    pub insecure: bool,
}

pub fn cli() -> Opt {
    Opt::from_args()
}
