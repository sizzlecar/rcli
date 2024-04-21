use self::jwt::JWTsubcommand;
use clap::Parser;
use enum_dispatch::enum_dispatch;

pub mod jwt;

#[derive(Parser, Debug)]
#[command(version= "0.1", about = "rcli", long_about = None)]
pub struct Rcli {
    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

#[derive(Parser, Debug)]
#[enum_dispatch(CmdExector)]
pub enum SubCommand {
    ///jwt
    #[clap(subcommand, about = "jwt tools", name = "jwt")]
    Jwt(JWTsubcommand),
}
