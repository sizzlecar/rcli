use std::{
    collections::HashMap,
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use enum_dispatch::enum_dispatch;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, EncodingKey};

/// command tool wrriter in rust
#[derive(Parser, Debug)]
#[command(version= "0.1", about = "rcli", long_about = None)]
struct Rcli {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser, Debug)]
#[enum_dispatch(CmdExector)]
enum SubCommand {
    ///jwt
    #[clap(subcommand, about = "jwt tools", name = "jwt")]
    Jwt(JWTsubcommand),
}

#[derive(Subcommand, Debug)]
#[enum_dispatch(CmdExector)]
enum JWTsubcommand {
    #[command(name = "sign", about = "gen jwt token")]
    Sign(SignParameter),

    #[command(name = "verify", about = "verify jwt token")]
    Verify(VerifyParameter),
}

#[derive(Parser, Debug)]
struct SignParameter {
    /// alg eg: HS256
    #[clap(long, required = true, value_parser = str2alg)]
    alg: String,

    /// subject eg: --sub acme
    #[clap(long)]
    sub: Option<String>,

    /// audience eg: --aud derive1
    #[clap(long)]
    aud: Option<String>,

    /// expiration time eg: --exp 14d
    #[clap(long, value_parser = str2timestamp)]
    exp: Option<u64>,

    /// secret eg: --secret xxxxxxxxx
    #[clap(long)]
    secret: Option<String>,

    /// private key eg: --private-key xxxxxxxxx or --private-key @/a/b/.x.pem
    #[clap(long, value_parser = str2pk)]
    private_key: Option<String>,
}

impl CmdExector for SignParameter {
    async fn execute(self) -> anyhow::Result<()> {
        let alg: Algorithm = self.alg.parse()?;
        let sub = self.sub;
        let aud = self.aud;
        let exp = self.exp;
        let secret = self.secret;
        let private_key = self.private_key;
        let encoding_key = match alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                EncodingKey::from_secret(get_content(secret).await?.as_slice())
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                EncodingKey::from_rsa_pem(get_content(private_key).await?.as_slice())?
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                EncodingKey::from_ec_pem(get_content(private_key).await?.as_slice())?
            }
            Algorithm::EdDSA => {
                EncodingKey::from_ed_pem(get_content(private_key).await?.as_slice())?
            }
        };
        let header = jsonwebtoken::Header::new(alg);
        let mut claims_map = HashMap::new();
        if let Some(sub) = sub {
            claims_map.insert("sub", sub);
        }
        if let Some(aud) = aud {
            claims_map.insert("aud", aud);
        }
        if let Some(exp) = exp {
            claims_map.insert("exp", exp.to_string());
        }
        let token = jsonwebtoken::encode(&header, &claims_map, &encoding_key)?;
        println!("{}", token);
        Ok(())
    }
}

async fn get_content(str_opt: Option<String>) -> Result<Vec<u8>, anyhow::Error> {
    if str_opt.is_none() {
        return Err(anyhow::Error::msg("no content"));
    }

    let str = str_opt.unwrap();
    if str.starts_with('@') {
        let file_path = str.trim_start_matches('@');
        Ok(tokio::fs::read(file_path).await?)
    } else {
        Ok(str.into_bytes())
    }
}

fn str2pk(str: &str) -> Result<String, anyhow::Error> {
    if str.starts_with('@') {
        let file_path = str.trim_start_matches('@');
        let _attr = fs::metadata(file_path)?;
    }
    Ok(str.into())
}

fn str2alg(str: &str) -> Result<String, anyhow::Error> {
    let _alg: Algorithm = str.parse()?;
    Ok(str.into())
}

fn str2timestamp(time_str: &str) -> Result<u64, anyhow::Error> {
    let duration: Duration = time_str.parse::<humantime::Duration>()?.into();
    let current_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    Ok(duration.as_secs() + current_secs)
}

#[derive(Parser, Debug)]
struct VerifyParameter {
    /// token eg: -t xxxxxx
    #[clap(short, required = true)]
    token: String,

    /// public key eg: --public-key xxxxxxxxx or --public-key @/a/b/.x.pem
    #[clap(long, value_parser = str2pk)]
    public_key: Option<String>,

    /// secret eg: --secret xxxxxxxxx
    #[clap(long)]
    secret: Option<String>,
}

impl CmdExector for VerifyParameter {
    async fn execute(self) -> anyhow::Result<()> {
        let token = self.token;
        let public_key = self.public_key;
        let secret = self.secret;
        let encoding_key = match public_key {
            Some(public_key) => {
                DecodingKey::from_rsa_pem(get_content(Some(public_key)).await?.as_slice())?
            }
            None => DecodingKey::from_secret(get_content(secret).await?.as_slice()),
        };
        // 解析 JWT 的头部
        let header = decode_header(&token)?;
        // 创建一个验证对象
        let mut validation = jsonwebtoken::Validation::new(header.alg); // 默认使用 HS256 算法
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims = Default::default();
        let result =
            jsonwebtoken::decode::<HashMap<String, String>>(&token, &encoding_key, &validation)?;
        println!("{:#?}", result);
        Ok(())
    }
}

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait CmdExector {
    async fn execute(self) -> anyhow::Result<()>;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Rcli = Rcli::parse();
    args.subcmd.execute().await?;
    Ok(())
}
