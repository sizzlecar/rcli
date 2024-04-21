mod cli;
mod process;

use crate::jwt::JWTsubcommand;
use crate::jwt::SignParameter;
use crate::jwt::VerifyParameter;
pub use cli::*;
use enum_dispatch::enum_dispatch;

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait CmdExector {
    async fn execute(self) -> anyhow::Result<()>;
}
