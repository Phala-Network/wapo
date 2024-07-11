use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::ops::Deref;
use scale::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

pub type WorkerPubkey = [u8; 32];
pub type Address = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
pub struct BoundedVec<T, const B: usize>(pub Vec<T>);

impl<T, const B: usize> BoundedVec<T, B> {
    pub fn max_len(&self) -> usize {
        B
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.len() >= B {
            return Err(value);
        }
        self.0.push(value);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        self.0.pop()
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }

    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const B: usize> Default for BoundedVec<T, B> {
    fn default() -> Self {
        Self(Default::default())
    }
}

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

impl<T, const B: usize> IntoIterator for BoundedVec<T, B> {
    type Item = <Vec<T> as IntoIterator>::Item;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Default)]
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
