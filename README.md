# ICE-Crypt

**Ice-Crypt** is a Rust implementation of the ICE (**I**nformation **C**oncealment **E**ngine) encryption algorithm.

## ICE
> [ICE] is a 64-bit private key block cipher, in the tradition of DES. However, unlike DES, it was designed to be secure against differential and linear cryptanalysis, and has no key complementation weaknesses or weak keys. In addition, its key size can be any multiple of 64 bits, whereas the DES key is limited to 56 bits.
> <br/> -- <cite>Matthew Kwan, Author of the ICE encryption algorithm</cite>

## Usage
Add this to your ```Cargo.toml```:

```toml
[dependencies]
ice-crypt = "1.0.0"
```

To encrypt a simple message, you can use the following code:

```src/main.rs```:
```rust
use ice_crypt::IceKey;

fn main() {
    let key: Vec<u8> = vec![67, 83, 71, 79, 16, 54, 0, 0, 132, 13, 0, 0, 97, 3, 0, 0];

    let message: &str = "My secret message";

    // Create a new IceKey instance
    let mut icekey = IceKey::new(2);

    // Set Private Key
    icekey.set(key);

    let encrypted_message: Vec<u8> = icekey.encrypt_all(message.as_bytes().to_vec());

    let decrypted_message: Vec<u8> = icekey.decrypt_all(encrypted_message);

    // Convert to string and remove 0 padding
    let mut output = std::str::from_utf8(&decrypted_message).unwrap();
    output = output.trim_end_matches('\0');

    assert_eq!(message, output);
}
```

## Documentation

TODO


## Original
The ICE encryption algorithm was designed and written by Matthew Kwan, checkout his C/C++ implementations of the algorithm on his [website](http://www.darkside.com.au/ice/index.html).


## License
**Ice-Crypt** is distributed under the terms of the GNU GENERAL PUBLIC LICENSE (Version 3).

See [LICENSE](LICENSE) for more details.
