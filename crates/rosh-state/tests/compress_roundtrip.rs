use rosh_state::compress::{CompressionAlgorithm, Compressor};

#[test]
fn compressor_roundtrip_zstd_and_lz4() {
    let payload_small = b"some small data that compresses a bit";
    let payload_large = vec![42u8; 4096];

    for (alg, data) in [
        (CompressionAlgorithm::Zstd, payload_small.as_slice()),
        (CompressionAlgorithm::Zstd, payload_large.as_slice()),
        (CompressionAlgorithm::Lz4, payload_small.as_slice()),
        (CompressionAlgorithm::Lz4, payload_large.as_slice()),
    ] {
        let c = Compressor::new(alg);
        let compressed = c.compress(data).expect("compress");
        let decompressed = c.decompress(&compressed).expect("decompress");
        assert_eq!(decompressed.as_slice(), data);
    }
}
