use crate::ChaCha20::chacha20_block;

// const REKEY_INTERVAL: u64 = 224; // packets

pub struct FSChaCha20 {
    key: [u8; 32], //key is always fixed to have 32 bytes
    block_counter: u32,
    chunk_counter: u64,
    keystream: Vec<u8>, // keystream changes so has to be a Vector of 1byte
    rekey_interval: u64,
}

impl FSChaCha20 {
    pub fn new(initial_key: [u8; 32], rekey_int: u64) -> Self {
        FSChaCha20 {
            key: initial_key,
            block_counter: 0,
            chunk_counter: 0,
            keystream: Vec::new(),
            rekey_interval: rekey_int,
        }
    }

    fn get_keystream_bytes(&mut self, nbytes: usize) -> Vec<u8> {
        while self.keystream.len() < nbytes {
            let mut nonce = [0u8; 12];
            let chunk_counter_bytes = (self.chunk_counter / self.rekey_interval).to_le_bytes();
            nonce[..8].copy_from_slice(&chunk_counter_bytes[..8]);

            let mut output = [0u8; 64];
            chacha20_block(&self.key, &nonce, self.block_counter, &mut output);
            self.keystream.extend_from_slice(&output);

            self.block_counter += 1;
        }

        let ret: Vec<u8> = self.keystream.drain(..nbytes).collect();
        ret
    }

    fn crypt(&mut self, chunk: &[u8]) -> Vec<u8> {
        let ks = self.get_keystream_bytes(chunk.len());
        let ret = chunk.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect();
        if (self.chunk_counter + 1) % self.rekey_interval == 0 {
            self.key = self.get_keystream_bytes(32).try_into().unwrap();
            self.block_counter = 0;
        }
        self.chunk_counter += 1;
        ret
    }

    pub fn encrypt(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.crypt(chunk)
    }

    pub fn decrypt(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.crypt(chunk)
    }
}

#[cfg(test)]
mod test {

    use crate::FsChaCha20::FSChaCha20;

    struct TestData<'a> {
        key: &'a str,
        chunk: &'a str,
        expected_output: &'a str,
        rekey_interval: u64,
    }

    fn initialize_test_data() -> Vec<TestData<'static>> {
        let keys: Vec<&'static str> = vec![
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        ];

        let chunks: Vec<& 'static str> = vec![
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
    ];

        let expected_outputs: Vec<& 'static str> = vec![
        "b710fd276ce42744442a36e7abf6eeba3e80492c535ed7405715c84d0a6e23f816eef2cd1599dc60ce629f080b83a75916dda76bfc50f715c81effee72383dfe15a382476658c09c8b6d22736b5a49557cee25ca7ce6ab872e8da42cbc48df97b088f958161ff6fad8260ab2ff86689853a2",
        "8cc5669354865e402093cc41583618bdbecd24134b5ad59f0cfb00695548ca0434100c086aa877f4373945e3e0ff31e1126f79712df6e52df9178b5714a001d7",
        "4c211add6cf37cf81227ae35f236fd6740270f92e0a99f4182d84de5b74a8f63a544495267e5f082778f2fb72087a2e10c4f90b9e3556255c0a4950aa5a5800f9e9042f10a6b88a2289f1322ea3eabeade054b3ca532002294b26852f5d227e420b49f315a7b1b3a9ba4b0b5f9967fac37fa27bd271f7b6497cd8df6706ad69f4aea78147a2bc79081c14d2367d0fb1c6a2844b51cb9ce16854a106a136879585fea2cae8eac39865b0c76c56006eed0e5c40efc63429efa18a26907336cde6c2df2044108e42a5fb48022fb161f025a55d43f10ca3ec282ab06116b5485e39d00485a0a899247fea7ccdd643344d0c2548a5db490d52ab013ce844c287de9f6a977c10b998ca9636a9ca444da915b6c33d16eec54ee64efb0e71aa8a616386f8290e58cb99a7cae3ac8ad14c7db70f44a1714169ebfc3c7b7895dd707b531adf3bc804dd2a2781e20c26c82aff57186dce5b735c0efbe8116e6ee5dee4ee2aa0267a47e623a41bd89eb6839403b57d7684ab7cb01495d",
        "657d217920ec1ca1b54f72ccb6445bfb69a3ab144f32057dee6409a81dece2c76b1f13c9fcdb5c35b45fd945e6c613d8a831be5525c7b2c46ed8c275404870bb284c6fd2d09614ff3d38301e5a70b8e19417c37fd27a7e3629e75fd6588610ddbdd60c29be724e990151b449c26ec5dbfb3720716e76c3fca6a85c220f4bfb",
    ];

        let rekey_intervals: Vec<u64> = vec![224, 224, 224, 224];

        let mut test_data: Vec<TestData> = Vec::new();

        for i in 0..keys.len() {
            let data = TestData {
                key: keys[i],
                chunk: chunks[i],
                expected_output: expected_outputs[i],
                rekey_interval: rekey_intervals[i],
            };
            test_data.push(data);
        }

        test_data
    }

    #[test]

    fn test_fschacha20() {
        let test_data = initialize_test_data();

        for data in &test_data {
            let key_bytes = hex::decode(data.key).expect("Failed to decode key hex string");
            let chunk_bytes = hex::decode(data.chunk).expect("Failed to decode chunk hex string");
            let expected_output_bytes = hex::decode(data.expected_output)
                .expect("Failed to decode expected output hex string");

            let key: [u8; 32] = key_bytes.as_slice().try_into().expect("Invalid key length");
            let rekey_interval = data.rekey_interval;
            let mut fs_chacha20 = FSChaCha20::new(key, rekey_interval);
            for _i in 0..(rekey_interval - 1) {
                fs_chacha20.encrypt(chunk_bytes.as_slice());
            }
            let output = fs_chacha20.encrypt(chunk_bytes.as_slice());
            assert_eq!(output, expected_output_bytes.as_slice());
        }
    }
}
