fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub async fn benchmark() {
    let mut buffer = sha256(b"init");
    loop {
        for _ in 0..10000 {
            buffer = sha256(&buffer);
        }
        std::hint::black_box(&buffer);
        wapo::time::breath().await;
    }
}
