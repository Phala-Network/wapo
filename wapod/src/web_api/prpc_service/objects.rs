use std::{path::Path, str::FromStr};

use anyhow::{bail, Context, Error, Result};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
enum HashAlgo {
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

pub(crate) async fn put_object<'a, R>(
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
