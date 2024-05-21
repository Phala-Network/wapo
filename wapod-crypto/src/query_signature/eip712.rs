use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::convert::TryInto;

use eip712_enc::{hash_structured_data, EIP712};

use super::{
    evm_ecdsa_recover, evm_pubkey_to_adderss, CertificateBody, Query, SignatureVerifyError,
};

use sp_core::{ecdsa::Public, H160, H256};

fn hex(s: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex_fmt::HexFmt(s.as_ref()))
}

pub(super) fn hash_query(query: &Query, proxy: bool) -> Result<H256> {
    let description = if proxy {
        "Authorized query that would be sent to a Wapod App"
    } else {
        "This is a query that would be sent to a Wapod App"
    };
    let address = hex(&query.address);
    let payload = hex(&query.payload);
    let path = &query.path;

    let value = json!({
        "primaryType": "WapodQuery",
        "domain": {
            "name": "Wapod Query",
            "version": "1"
        },
        "message": {
            "description": description,
            "address": address,
            "path": path,
            "payload": payload,
        },
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
            ],
            "WapodQuery": [
                { "name": "description", "type": "string" },
                { "name": "address", "type": "bytes" },
                { "name": "path", "type": "string" },
                { "name": "payload", "type": "bytes" }
            ],
        }
    });
    let data = serde_json::from_value::<EIP712>(value).context("Failed to serialize query")?;
    Ok(hash_structured_data(data).map_err(|err| anyhow!("{err:?}"))?)
}

pub(super) fn hash_cert(query: &CertificateBody) -> Result<H256> {
    let public_key = hex(&query.pubkey);
    let scopes = query
        .scopes
        .iter()
        .map(|s| {
            json!({
                   "address": hex(&s.app),
                   "paths": s.resources,
            })
        })
        .collect::<Vec<_>>();

    let expiration_time = query.expiration.to_string();

    let value = json!({
        "primaryType": "Certificate",
        "domain": {
            "name": "Wapod Query",
            "version": "1"
        },
        "message": {
            "description": "This is a certificate that can be used to sign a query that would be sent to a Wapod App",
            "publicKey": public_key,
            "expirationTime": expiration_time,
            "scopes": scopes
        },
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
            ],
            "Certificate": [
                { "name": "description", "type": "string" },
                { "name": "publicKey", "type": "bytes" },
                { "name": "expirationTime", "type": "string" },
                { "name": "scopes", "type": "Scope[]" }
            ],
            "Scope": [
                { "name": "address", "type": "bytes" },
                { "name": "paths", "type": "string[]" }
            ]
        }
    });
    let data =
        serde_json::from_value::<EIP712>(value).context("Failed to serialize certificate")?;
    Ok(hash_structured_data(data).map_err(|err| anyhow!("{err:?}"))?)
}

pub(crate) fn eip721_verify(
    address: H160,
    signature: &[u8],
    message_hash: [u8; 32],
) -> Result<Public, SignatureVerifyError> {
    let signature = signature
        .try_into()
        .or(Err(SignatureVerifyError::InvalidSignature))?;
    let recovered_pubkey = evm_ecdsa_recover(signature, message_hash)?;
    let recovered_address = evm_pubkey_to_adderss(&recovered_pubkey)?;
    if recovered_address != address {
        return Err(SignatureVerifyError::InvalidSignature);
    }
    Ok(recovered_pubkey)
}

#[test]
fn signing_query_works() {
    let user_address = hex_literal::hex!("77bB3D64EA13E4f0BeaFDd5d92508d4643Bb09cb").into();
    let query = super::Query {
        address: hex_literal::hex!("1234").to_vec(),
        path: "/api/resource".into(),
        payload: hex_literal::hex!("abcdef").to_vec(),
    };
    let mm_signature = hex_literal::hex!("d2cf3fc16983e15ba3c58f486725b81a2edd744a2b56dbf949af78f1beadbef036783bdde9d866c0309af8c95dfeea5ffffbdb840850432ae0065f40efd0cced1b");
    let msg_hash = hash_query(&query, false).unwrap();

    eip721_verify(user_address, &mm_signature, msg_hash.0).unwrap();

    let mm_signature_proxyied = hex_literal::hex!("4a0b97f273f43be3b7b91304114d41ec26ac4f265a9f6babc1c59c6ce8f5c9266d1b6e42b88efced4e0026cc19da93d98a8d401bd2e064781caa1db8e8df1e771b");
    let msg_hash = hash_query(&query, true).unwrap();
    eip721_verify(user_address, &mm_signature_proxyied, msg_hash.0).unwrap();
}

#[test]
fn signing_cert_works() {
    let user_address = hex_literal::hex!("77bB3D64EA13E4f0BeaFDd5d92508d4643Bb09cb").into();
    let mm_signature = hex_literal::hex!("916e69889759d755d4e7697615e906d4b097d8c0293dc66e749ca28331a4bc151e76ecad2f85c4a91b995d93f3121b0a4cb342916209fd96fe266bec009b74f11c");

    let cert = super::CertificateBody {
        pubkey: hex_literal::hex!("1234").to_vec(),
        expiration: 1672531199,
        scopes: vec![
            super::Scope {
                app: hex_literal::hex!("12").to_vec(),
                resources: vec!["/res1".to_string(), "/res2".to_string()],
            },
            super::Scope {
                app: hex_literal::hex!("34").to_vec(),
                resources: vec!["/res1".to_string()],
            },
        ],
    };
    let msg_hash = hash_cert(&cert).unwrap();
    eip721_verify(user_address, &mm_signature, msg_hash.0).unwrap();
}
