use digest::{generic_array::GenericArray, Digest};
use futures::prelude::*;
use hex::FromHex;
use serde::Deserialize;
use sha2::Sha256;
use std::{convert::TryFrom, io};

#[derive(Debug)]
pub enum Checksum {
    Sha256(GenericArray<u8, <Sha256 as Digest>::OutputSize>),
}

#[derive(Debug, Error)]
pub enum ChecksumError {
    #[error("expected {}, found {}", hex::encode(_0), hex::encode(_1))]
    Invalid(Box<[u8]>, Box<[u8]>),
    #[error("I/O error encountered while reading from reader")]
    IO(#[from] io::Error),
}

pub enum SumStr<'a> {
    Sha256(&'a str),
}

#[derive(Deserialize)]
pub enum SumStrBuf {
    Sha256(String),
}

impl SumStrBuf {
    pub fn as_ref(&self) -> SumStr {
        match self {
            SumStrBuf::Sha256(string) => SumStr::Sha256(string.as_str()),
        }
    }
}

impl<'a> TryFrom<SumStr<'a>> for Checksum {
    type Error = hex::FromHexError;

    fn try_from(input: SumStr) -> Result<Self, Self::Error> {
        match input {
            SumStr::Sha256(sum) => {
                <[u8; 32]>::from_hex(sum).map(GenericArray::from).map(Checksum::Sha256)
            }
        }
    }
}

impl Checksum {
    pub async fn validate<F: AsyncRead + Unpin>(
        &self,
        reader: F,
        buffer: &mut [u8],
    ) -> Result<(), ChecksumError> {
        match self {
            Checksum::Sha256(sum) => checksum::<Sha256, F>(reader, buffer, sum).await,
        }
    }
}

async fn checksum<D: Digest, F: AsyncRead + Unpin>(
    mut reader: F,
    buffer: &mut [u8],
    expected: &GenericArray<u8, D::OutputSize>,
) -> Result<(), ChecksumError> {
    let mut hasher = D::new();
    let mut read;

    loop {
        read = reader.read(buffer).await.map_err(ChecksumError::IO)?;

        if read == 0 {
            let result = hasher.finalize();
            return if result == *expected {
                Ok(())
            } else {
                let expected = expected.clone().into_iter().collect::<Vec<u8>>().into();
                let actual = result.into_iter().collect::<Vec<u8>>().into();
                Err(ChecksumError::Invalid(expected, actual))
            };
        }

        hasher.update(&buffer[..read]);
    }
}
