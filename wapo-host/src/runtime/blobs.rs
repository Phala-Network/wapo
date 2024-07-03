use std::{
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::{bail, Context, Error, Result};
use scale::{Decode, Encode};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone)]
pub struct BlobLoader {
    store_dir: Arc<PathBuf>,
}

impl BlobLoader {
    pub fn new(store_dir: impl AsRef<Path>) -> Self {
        Self {
            store_dir: Arc::new(store_dir.as_ref().to_path_buf()),
        }
    }

    pub fn get(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        get_object(self.store_dir.as_path(), hash)
    }

    pub async fn put<'a, R>(&self, hash: &str, data: &'a mut R) -> Result<String>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        put_object(self.store_dir.as_path(), hash, data).await
    }

    pub fn remove(&self, hash: &str) -> Result<()> {
        let hash = HashValue::from_str(hash).map_err(Error::msg)?;
        std::fs::remove_file(self.path(&hash.hash))?;
        Ok(())
    }

    pub fn path(&self, hash: &[u8]) -> PathBuf {
        self.store_dir.join(hex::encode(hash))
    }

    pub fn exists(&self, hash: &str) -> bool {
        let Ok(hash) = HashValue::from_str(hash) else {
            return false;
        };
        self.path(&hash.hash).exists()
    }
}

#[derive(Debug, Encode, Decode, Clone, Copy)]
pub enum HashAlgo {
    Sha256,
    Sha512,
}

pub struct HashValue {
    pub algo: HashAlgo,
    pub hash: Vec<u8>,
}

impl FromStr for HashAlgo {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err("Invalid hash algorithm"),
        }
    }
}

impl FromStr for HashValue {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ':');
        let algo = parts.next().ok_or("missing hash algorithm")?;
        let hash = parts.next().unwrap_or_default();
        let algo = HashAlgo::from_str(algo)?;
        let hash = hex::decode(hash).map_err(|_| "invalid hash value")?;
        Ok(Self { algo, hash })
    }
}

impl Display for HashValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            match self.algo {
                HashAlgo::Sha256 => "sha256",
                HashAlgo::Sha512 => "sha512",
            },
            hex::encode(&self.hash)
        )
    }
}

enum Hasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }
    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize().as_slice().to_vec(),
            Self::Sha512(h) => h.finalize().as_slice().to_vec(),
        }
    }

    fn hash(data: &[u8], hash_algo: HashAlgo) -> Vec<u8> {
        let mut hasher = match hash_algo {
            HashAlgo::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            HashAlgo::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        };
        hasher.update(data);
        hasher.finalize()
    }
}

async fn hash_file(path: impl AsRef<Path>, hash_algo: HashAlgo) -> Result<Vec<u8>> {
    let path = path.as_ref();
    let file = tokio::fs::File::open(path)
        .await
        .context("failed to open object file")?;
    let mut hasher = match hash_algo {
        HashAlgo::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
        HashAlgo::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
    };
    let mut file = tokio::io::BufReader::new(file);
    let mut buf = [0; 4096];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .context("failed to read object file")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

pub async fn put_object<'a, R>(
    path: impl AsRef<Path>,
    hash: &str,
    data: &'a mut R,
) -> Result<String>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let hash = HashValue::from_str(hash).map_err(Error::msg)?;
    let path = path.as_ref();
    let tmpdir = path.join(".tmp");
    std::fs::create_dir_all(&tmpdir).context("failed to create blobs directory")?;

    let tmp_filepath = tmpdir.join(uuid::Uuid::new_v4().to_string());
    let mut tmpfile = tokio::fs::File::create(&tmp_filepath)
        .await
        .context("failed to create temporary object file")?;
    let _guard = scopeguard::guard((), |_| {
        let _ = std::fs::remove_file(&tmp_filepath);
    });
    tokio::io::copy(data, &mut tmpfile)
        .await
        .context("failed to write object file")?;
    tmpfile
        .sync_all()
        .await
        .context("failed to sync object file")?;
    drop(tmpfile);

    // Make sure the hash of the file is correct
    let actual_hash = hash_file(&tmp_filepath, hash.algo).await?;
    if !hash.hash.is_empty() && actual_hash != hash.hash {
        bail!(
            "blob hash mismatch, actual: {}, expected: {}",
            hex_fmt::HexFmt(&actual_hash),
            hex_fmt::HexFmt(&hash.hash)
        );
    }
    let key = hex::encode(&actual_hash);
    std::fs::rename(&tmp_filepath, path.join(key))
        .context("failed to move object file to blobs directory")?;
    let mut hash = hash;
    hash.hash = actual_hash;
    Ok(hash.to_string())
}

pub fn get_object(blobs_dir: impl AsRef<Path>, hash: &str) -> Result<Option<Vec<u8>>> {
    let hash = HashValue::from_str(hash).map_err(Error::msg)?;
    let result = std::fs::read(blobs_dir.as_ref().join(hex::encode(&hash.hash)));
    let data = match result {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("failed to read object file"),
    };
    let actual_hash = Hasher::hash(&data, hash.algo);
    if actual_hash != hash.hash {
        bail!(
            "blob hash mismatch, actual hash is {}",
            hex_fmt::HexFmt(actual_hash)
        );
    }
    Ok(Some(data))
}
