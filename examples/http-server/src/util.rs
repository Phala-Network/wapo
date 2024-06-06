pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut sha = sha2::Sha256::new();
    sha.update(data);
    sha.finalize().into()
}
