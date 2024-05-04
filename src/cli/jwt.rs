use std::{
    collections::HashMap,
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use enum_dispatch::enum_dispatch;
use jsonwebtoken::Algorithm;

use crate::{
    process::{decode_verify, encode},
    CmdExector,
};

#[derive(Subcommand, Debug)]
#[enum_dispatch(CmdExector)]
pub enum JWTsubcommand {
    #[command(name = "sign", about = "gen jwt token")]
    Sign(SignParameter),

    #[command(name = "verify", about = "verify jwt token")]
    Verify(VerifyParameter),
}

#[derive(Parser, Debug)]
pub struct SignParameter {
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
        let sub = self.sub;
        let aud = self.aud;
        let exp = self.exp;
        let secret = self.secret;
        let private_key = self.private_key;
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
        let token = encode(&self.alg, &claims_map, secret, private_key).await?;
        println!("{}", token);
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct VerifyParameter {
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
        let result = decode_verify::<HashMap<String, String>>(&token, secret, public_key).await?;
        println!("{:#?}", result);
        Ok(())
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str2pk_file_not_exist() {
        let file_path = "@/a/b/.x.pem";
        assert!(str2pk(file_path).is_err());
    }

    #[test]
    fn test_str2pk_file_exist() {
        // Test when the input is a file path
        let file_path = "@./README.md";
        let res = str2pk(file_path);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), file_path);
    }

    #[test]
    fn test_str2pk_str() {
        let key = "xxxxxxxx";
        let res = str2pk(key);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key);
    }

    #[test]
    fn test_str2alg_error() {
        // Test when the input is an invalid algorithm
        let invalid_alg = "INVALID";
        assert!(str2alg(invalid_alg).is_err());
    }

    #[test]
    fn test_str2alg() {
        // Test when the input is a valid algorithm
        let alg = "HS256";
        let res = str2alg(alg);
        assert!(res.is_ok());
        assert_eq!(str2alg(alg).unwrap(), alg);
    }

    #[test]
    fn test_str2timestamp() {
        // Test when the input is a valid duration string
        let time_str = "14d";
        let current_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let expected_timestamp =
            current_secs + humantime::parse_duration(time_str).unwrap().as_secs();
        assert_eq!(str2timestamp(time_str).unwrap(), expected_timestamp);
    }

    #[test]
    fn test_str2timestamp_err() {
        // Test when the input is an invalid duration string
        let invalid_time_str = "invalid";
        assert!(str2timestamp(invalid_time_str).is_err());
    }
}
