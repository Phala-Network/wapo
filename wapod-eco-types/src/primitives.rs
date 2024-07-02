use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::ops::Deref;
use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

pub type WorkerPubkey = [u8; 32];
pub type Address = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
pub struct BoundedVec<T, const B: usize>(pub Vec<T>);

impl<T: Decode, const B: usize> Decode for BoundedVec<T, B> {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let vec = Vec::<T>::decode(input)?;
        if vec.len() > B {
            return Err(scale::Error::from("BoundedVec: length exceeds bound"));
        }
        Ok(Self(vec))
    }
}

impl<T, const B: usize> Deref for BoundedVec<T, B> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<T, const B: usize> From<Vec<T>> for BoundedVec<T, B> {
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T, const B: usize> From<&[T]> for BoundedVec<T, B>
where
    T: Clone,
{
    fn from(slice: &[T]) -> Self {
        Self(slice.to_vec())
    }
}

impl<T, const B: usize> From<BoundedVec<T, B>> for Vec<T> {
    fn from(bounded_vec: BoundedVec<T, B>) -> Self {
        bounded_vec.0
    }
}
impl<T: MaxEncodedLen, const B: usize> MaxEncodedLen for BoundedVec<T, B> {
    fn max_encoded_len() -> usize {
        B * T::max_encoded_len()
    }
}

impl<T: TypeInfo + 'static, const B: usize> TypeInfo for BoundedVec<T, B> {
    type Identity = <Vec<T> as TypeInfo>::Identity;

    fn type_info() -> scale_info::Type {
        <Vec<T> as TypeInfo>::type_info()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
pub struct BoundedString<const B: usize>(pub String);

impl<const B: usize> Deref for BoundedString<B> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const B: usize> From<String> for BoundedString<B> {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<const B: usize> From<&str> for BoundedString<B> {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl<const B: usize> From<BoundedString<B>> for String {
    fn from(bounded_string: BoundedString<B>) -> Self {
        bounded_string.0
    }
}

impl<const B: usize> TypeInfo for BoundedString<B> {
    type Identity = <String as TypeInfo>::Identity;

    fn type_info() -> scale_info::Type {
        <String as TypeInfo>::type_info()
    }
}

impl<const B: usize> Decode for BoundedString<B> {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let s = String::decode(input)?;
        if s.as_bytes().len() > B {
            return Err(scale::Error::from("BoundedString: length exceeds bound"));
        }
        Ok(Self(s))
    }
}

impl<const B: usize> core::fmt::Display for BoundedString<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<const B: usize> MaxEncodedLen for BoundedString<B> {
    fn max_encoded_len() -> usize {
        B
    }
}
