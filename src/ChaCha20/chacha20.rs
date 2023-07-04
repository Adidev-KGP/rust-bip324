fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, output: &mut [u8; 64]) {
    let mut state = [0u32; 16];
    let mut input = [0u8; 64];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 0..16 {
        input[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    let mut working_state = state;
    for _i in 0..10 {
        quarter_round(&mut working_state, 0, 4, 8, 12);
        quarter_round(&mut working_state, 1, 5, 9, 13);
        quarter_round(&mut working_state, 2, 6, 10, 14);
        quarter_round(&mut working_state, 3, 7, 11, 15);
        quarter_round(&mut working_state, 0, 5, 10, 15);
        quarter_round(&mut working_state, 1, 6, 11, 12);
        quarter_round(&mut working_state, 2, 7, 8, 13);
        quarter_round(&mut working_state, 3, 4, 9, 14);
    }

    for i in 0..16 {
        working_state[i] = working_state[i].wrapping_add(state[i]);
    }
    for i in 0..16 {
        output[4 * i..4 * i + 4].copy_from_slice(&working_state[i].to_le_bytes());
    }
}

#[cfg(test)]
mod test {
    use crate::ChaCha20::chacha20_block;

    struct TestData<'a> {
        key: &'a str,
        nonce: &'a str,
        counter: u32,
        expected_output: &'a str,
    }

    fn initialize_test_data() -> Vec<TestData<'static>> {
        let keys: Vec<&'static str> = vec![
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "00ff000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ];

        let nonces: Vec<&'static str> = vec![
            "000000090000004a00000000",
            "000000000000000000000000",
            "000000000000000000000000",
            "000000000000000000000000",
            "000000000000000000000000",
            "000000000000000000000002",
        ];

        let counters: Vec<u32> = vec![1, 0, 1, 1, 2, 0];

        let expected_outputs: Vec<&'static str> = vec![
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
            "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
            "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
            "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
        ];

        let mut test_data: Vec<TestData> = Vec::new();

        for i in 0..keys.len() {
            let data = TestData {
                key: keys[i],
                nonce: nonces[i],
                counter: counters[i],
                expected_output: expected_outputs[i],
            };
            test_data.push(data);
        }

        test_data
    }

    #[test]

    fn test_chacha20_block() {
        let test_data = initialize_test_data();

        for data in &test_data {
            let key_bytes = hex::decode(data.key).expect("Failed to decode key hex string");
            let nonce_bytes = hex::decode(data.nonce).expect("Failed to decode nonce hex string");

            let expected_output_bytes = hex::decode(data.expected_output)
                .expect("Failed to decode expected output hex string");

            let key: [u8; 32] = key_bytes.as_slice().try_into().expect("Invalid key length");
            let nonce: [u8; 12] = nonce_bytes
                .as_slice()
                .try_into()
                .expect("Invalid nonce length");

            let mut output: [u8; 64] = [0; 64];

            chacha20_block(&key, &nonce, data.counter, &mut output);

            assert_eq!(output, expected_output_bytes.as_slice());
        }
    }
}
