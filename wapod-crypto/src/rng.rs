use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

pub trait CryptoRng {
    fn crypto_gen<T>(&mut self) -> T
    where
        Standard: Distribution<T>;
}

impl<G> CryptoRng for G
where
    G: rand::CryptoRng + Rng,
{
    fn crypto_gen<T>(&mut self) -> T
    where
        Standard: Distribution<T>,
    {
        self.gen()
    }
}
