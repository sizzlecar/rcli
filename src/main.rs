use clap::Parser;
use rcli::CmdExector;
use rcli::Rcli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Rcli = Rcli::parse();
    args.subcmd.execute().await?;
    Ok(())
}
