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
    let str: String = str_opt.ok_or_else(|| anyhow::Error::msg("no content"))?;
    if str.starts_with('@') {
        let file_path = str.trim_start_matches('@');
        Ok(tokio::fs::read(file_path).await?)
    } else {
        Ok(str.into_bytes())
    }
}

//create unit tests
#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use super::*;

    #[tokio::test]
    async fn test_encode_decode() {
        // Test data
        let alg = "HS256";
        let mut claims = HashMap::<String, String>::new();
        claims.insert("sub".to_string(), "test claims".to_string());
        let secret = Some("secret".to_string());
        let private_key = None;

        // Encode
        let encoded_token = encode(alg, &claims, secret.clone(), private_key.clone()).await;
        assert!(encoded_token.is_ok());

        // Decode and verify
        let decoded_token: Result<TokenData<HashMap<String, String>>, anyhow::Error> =
            decode_verify(&encoded_token.unwrap(), secret, private_key).await;
        assert!(decoded_token.is_ok());

        // Check if the decoded claims match the original claims
        let token_data = decoded_token.unwrap();
        assert_eq!(token_data.claims.get("sub").unwrap(), "test claims");
    }

    #[tokio::test]
    async fn test_get_content() {
        // Test data
        let str_opt = Some("test content".to_string());

        // Get content from string
        let content = get_content(str_opt).await;
        assert!(content.is_ok());
        assert_eq!(content.unwrap(), b"test content");

        // Get content from file
        let str_opt = Some("@./README.md".to_string());
        let content = get_content(str_opt).await;
        assert!(content.is_ok());
        // Assert the content is read from the file correctly
    }
}
