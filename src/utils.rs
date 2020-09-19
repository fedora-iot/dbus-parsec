use ring::aead;

pub struct CounterNonce {
    counter: u8,
}

impl CounterNonce {
    pub fn new() -> Self {
        CounterNonce { counter: 0 }
    }
}

impl aead::NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        self.counter += 1;

        if self.counter >= u8::MAX {
            return Err(ring::error::Unspecified {});
        }

        let mut nonce = [0; 12];
        nonce[0] = self.counter;

        aead::Nonce::try_assume_unique_for_key(&nonce)
    }
}
