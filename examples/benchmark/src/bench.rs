fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub async fn benchmark() {
    let mut init = sha256(b"init");
    loop {
        for _ in 0..10000 {
            init = sha256(&init);
        }
        std::hint::black_box(&init);
        wapo::time::breath().await;
    }
}
