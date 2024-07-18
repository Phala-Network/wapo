/// Input that adds infinite number of zero after wrapped input.
pub(crate) struct TrailingZeroInput<'a>(&'a [u8]);

impl<'a> TrailingZeroInput<'a> {
    /// Create a new instance from the given byte array.
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl<'a> scale::Input for TrailingZeroInput<'a> {
    fn remaining_len(&mut self) -> Result<Option<usize>, scale::Error> {
        Ok(None)
    }

    fn read(&mut self, into: &mut [u8]) -> Result<(), scale::Error> {
        let len_from_inner = into.len().min(self.0.len());
        into[..len_from_inner].copy_from_slice(&self.0[..len_from_inner]);
        for i in &mut into[len_from_inner..] {
            *i = 0;
        }
        self.0 = &self.0[len_from_inner..];

        Ok(())
    }
}
