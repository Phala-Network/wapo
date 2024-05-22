use sp_core::{blake2_256, keccak_256};
use wapod_crypto::ContentType;

pub fn quote(content_type: ContentType, data: &[u8]) -> Option<Vec<u8>> {
    let hash = match content_type {
        ContentType::WorkerAttestation => blake2_256(data),
        _ => {
            let final_message = content_type.wrap_message(data);
            keccak_256(&final_message)
        }
    };
    let mut user_data = hash.to_vec();
    user_data.extend_from_slice([0u8; 32].as_ref());
    std::fs::write("/dev/attestation/user_report_data", &user_data).ok()?;
    std::fs::read("/dev/attestation/quote").ok()
}
