use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::{bail, Context, Error, Result};
use scale::{Decode, Encode};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone)]
pub struct ObjectLoader {
    objects_path: Arc<PathBuf>,
}

impl ObjectLoader {
    pub fn new(objects_path: impl AsRef<Path>) -> Self {
        Self {
            objects_path: Arc::new(objects_path.as_ref().to_path_buf()),
        }
    }

    pub fn get_object(&self, hash: &[u8], hash_algo: &str) -> Result<Option<Vec<u8>>> {
        get_object(self.objects_path.as_path(), hash, hash_algo)
    }

    pub async fn put_object<'a, R>(
        &self,
        hash: &[u8],
        data: &'a mut R,
        hash_algo: &str,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        put_object(self.objects_path.as_path(), hash, data, hash_algo).await
    }

    pub fn path(&self, hash: &[u8]) -> PathBuf {
        self.objects_path.join(hex::encode(hash))
    }

    pub fn exists(&self, hash: &[u8]) -> bool {
        self.path(hash).exists()
    }
}

#[derive(Debug, Encode, Decode)]
pub enum HashAlgo {
    Sha256,
    Sha512,
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
        .context("Failed to open object file")?;
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
            .context("Failed to read object file")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

pub async fn put_object<'a, R>(
    path: impl AsRef<Path>,
    hash: &[u8],
    data: &'a mut R,
    hash_algo: &str,
) -> Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let hash_algo = HashAlgo::from_str(hash_algo).map_err(Error::msg)?;
    let key = hex::encode(hash);

    let path = path.as_ref();
    let tmpdir = path.join(".tmp");
    std::fs::create_dir_all(&tmpdir).context("Failed to create objects directory")?;

    let tmp_filepath = tmpdir.join(&uuid::Uuid::new_v4().to_string());
    let mut tmpfile = tokio::fs::File::create(&tmp_filepath)
        .await
        .context("Failed to create temporary object file")?;
    let _guard = scopeguard::guard((), |_| {
        let _ = std::fs::remove_file(&tmp_filepath);
    });
    tokio::io::copy(data, &mut tmpfile)
        .await
        .context("Failed to write object file")?;
    tmpfile
        .sync_all()
        .await
        .context("Failed to sync object file")?;
    drop(tmpfile);

    // Make sure the hash of the file is correct
    let actual_hash = hash_file(&tmp_filepath, hash_algo).await?;
    if actual_hash != hash {
        bail!(
            "Object file hash mismatch, actual hash is {}",
            hex_fmt::HexFmt(actual_hash)
        );
    }
    std::fs::rename(&tmp_filepath, path.join(&key))
        .context("Failed to move object file to objects directory")?;
    drop(_guard);
    Ok(())
}

pub fn get_object(
    objects_path: impl AsRef<Path>,
    hash: &[u8],
    hash_algo: &str,
) -> Result<Option<Vec<u8>>> {
    let hash_algo = HashAlgo::from_str(hash_algo).map_err(Error::msg)?;
    let result = std::fs::read(objects_path.as_ref().join(hex::encode(hash)));
    let data = match result {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("Failed to read object file"),
    };
    let actual_hash = Hasher::hash(&data, hash_algo);
    if actual_hash != hash {
        bail!(
            "Object file hash mismatch, actual hash is {}",
            hex_fmt::HexFmt(actual_hash)
        );
    }
    Ok(Some(data))
}
