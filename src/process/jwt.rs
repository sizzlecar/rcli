use jsonwebtoken::{decode_header, Algorithm, DecodingKey, EncodingKey, TokenData};
use serde::{de::DeserializeOwned, Serialize};

pub async fn encode<T: Serialize>(
    alg: &str,
    claims: &T,
    secret: Option<String>,
    private_key: Option<String>,
) -> Result<String, anyhow::Error> {
    let alg: Algorithm = alg.parse()?;
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
        Algorithm::EdDSA => EncodingKey::from_ed_pem(get_content(private_key).await?.as_slice())?,
    };
    let header = jsonwebtoken::Header::new(alg);

    let token = jsonwebtoken::encode(&header, claims, &encoding_key)?;
    Ok(token)
}

pub async fn decode_verify<T: DeserializeOwned>(
    token: &str,
    secret: Option<String>,
    public_key: Option<String>,
) -> Result<TokenData<T>, anyhow::Error> {
    let encoding_key = match public_key {
        Some(public_key) => {
            DecodingKey::from_rsa_pem(get_content(Some(public_key)).await?.as_slice())?
        }
        None => DecodingKey::from_secret(get_content(secret).await?.as_slice()),
    };
    // 解析 JWT 的头部
    let header = decode_header(token)?;
    // 创建一个验证对象
    let mut validation = jsonwebtoken::Validation::new(header.alg); // 默认使用 HS256 算法
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims = Default::default();
    let result = jsonwebtoken::decode::<T>(token, &encoding_key, &validation)?;
    Ok(result)
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
