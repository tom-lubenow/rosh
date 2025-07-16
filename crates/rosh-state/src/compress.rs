//! Compression support for state synchronization
//!
//! Provides both Zstd and LZ4 compression algorithms

use crate::StateError;
use std::io::{Read, Write};

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum CompressionAlgorithm {
    /// Zstandard compression (better ratio, slightly slower)
    #[cfg_attr(feature = "clap", value(name = "zstd"))]
    Zstd,
    /// LZ4 compression (faster, lower ratio)
    #[cfg_attr(feature = "clap", value(name = "lz4"))]
    Lz4,
}

/// Compressor wrapper supporting multiple algorithms
#[derive(Debug)]
pub struct Compressor {
    algorithm: CompressionAlgorithm,
    compression_level: i32,
}

impl Compressor {
    /// Create a new compressor with specified algorithm
    pub fn new(algorithm: CompressionAlgorithm) -> Self {
        Self {
            algorithm,
            compression_level: match algorithm {
                CompressionAlgorithm::Zstd => 3, // Default zstd level
                CompressionAlgorithm::Lz4 => 0,  // LZ4 doesn't use levels in same way
            },
        }
    }

    /// Set compression level (algorithm-specific)
    pub fn with_level(mut self, level: i32) -> Self {
        self.compression_level = level;
        self
    }

    /// Compress data
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, StateError> {
        match self.algorithm {
            CompressionAlgorithm::Zstd => self.compress_zstd(data),
            CompressionAlgorithm::Lz4 => self.compress_lz4(data),
        }
    }

    /// Decompress data
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, StateError> {
        match self.algorithm {
            CompressionAlgorithm::Zstd => self.decompress_zstd(data),
            CompressionAlgorithm::Lz4 => self.decompress_lz4(data),
        }
    }

    /// Compress using Zstandard
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, StateError> {
        let mut encoder = zstd::Encoder::new(Vec::new(), self.compression_level).map_err(|e| {
            StateError::CompressionError(format!("Failed to create zstd encoder: {e}"))
        })?;

        encoder.write_all(data).map_err(|e| {
            StateError::CompressionError(format!("Failed to write to zstd encoder: {e}"))
        })?;

        encoder.finish().map_err(|e| {
            StateError::CompressionError(format!("Failed to finish zstd encoding: {e}"))
        })
    }

    /// Decompress using Zstandard
    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, StateError> {
        let mut decoder = zstd::Decoder::new(data).map_err(|e| {
            StateError::CompressionError(format!("Failed to create zstd decoder: {e}"))
        })?;

        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).map_err(|e| {
            StateError::CompressionError(format!("Failed to decompress zstd data: {e}"))
        })?;

        Ok(decompressed)
    }

    /// Compress using LZ4
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>, StateError> {
        Ok(lz4_flex::compress_prepend_size(data))
    }

    /// Decompress using LZ4
    fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>, StateError> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| StateError::CompressionError(format!("LZ4 decompression failed: {e}")))
    }
}

/// Adaptive compressor that chooses algorithm based on data characteristics
pub struct AdaptiveCompressor {
    zstd: Compressor,
    lz4: Compressor,
    size_threshold: usize,
}

impl Default for AdaptiveCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveCompressor {
    /// Create a new adaptive compressor
    pub fn new() -> Self {
        Self {
            zstd: Compressor::new(CompressionAlgorithm::Zstd),
            lz4: Compressor::new(CompressionAlgorithm::Lz4),
            size_threshold: 1024, // Use LZ4 for small data
        }
    }

    /// Compress data, choosing algorithm based on size
    pub fn compress(&self, data: &[u8]) -> Result<(CompressionAlgorithm, Vec<u8>), StateError> {
        if data.len() < self.size_threshold {
            // Use LZ4 for small data (faster)
            self.lz4
                .compress(data)
                .map(|c| (CompressionAlgorithm::Lz4, c))
        } else {
            // Use Zstd for larger data (better ratio)
            self.zstd
                .compress(data)
                .map(|c| (CompressionAlgorithm::Zstd, c))
        }
    }

    /// Decompress data with specified algorithm
    pub fn decompress(
        &self,
        algorithm: CompressionAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, StateError> {
        match algorithm {
            CompressionAlgorithm::Zstd => self.zstd.decompress(data),
            CompressionAlgorithm::Lz4 => self.lz4.decompress(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zstd_compression() {
        let compressor = Compressor::new(CompressionAlgorithm::Zstd);
        let data = b"Hello, world! This is a test of compression.".repeat(10);

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_lz4_compression() {
        let compressor = Compressor::new(CompressionAlgorithm::Lz4);
        let data = b"Hello, world! This is a test of compression.".repeat(10);

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_adaptive_compression() {
        let compressor = AdaptiveCompressor::new();

        // Small data should use LZ4
        let small_data = b"Small";
        let (algo1, _) = compressor.compress(small_data).unwrap();
        assert_eq!(algo1, CompressionAlgorithm::Lz4);

        // Large data should use Zstd
        let large_data = vec![0u8; 2000];
        let (algo2, _) = compressor.compress(&large_data).unwrap();
        assert_eq!(algo2, CompressionAlgorithm::Zstd);
    }
}
