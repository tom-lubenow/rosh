use anyhow::Result;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct NetworkConditions {
    /// Packet loss probability (0.0 to 1.0)
    pub packet_loss: f64,
    /// Base latency in milliseconds
    pub latency_ms: u64,
    /// Latency jitter in milliseconds
    pub jitter_ms: u64,
    /// Bandwidth limit in bytes per second (0 = unlimited)
    pub bandwidth_bps: u64,
    /// Packet reordering probability (0.0 to 1.0)
    pub reorder_probability: f64,
    /// Maximum reorder distance
    pub max_reorder_distance: usize,
    /// Duplicate packet probability (0.0 to 1.0)
    pub duplicate_probability: f64,
}

impl Default for NetworkConditions {
    fn default() -> Self {
        Self {
            packet_loss: 0.0,
            latency_ms: 0,
            jitter_ms: 0,
            bandwidth_bps: 0,
            reorder_probability: 0.0,
            max_reorder_distance: 3,
            duplicate_probability: 0.0,
        }
    }
}

impl NetworkConditions {
    /// Perfect network conditions
    pub fn perfect() -> Self {
        Self::default()
    }

    /// Typical mobile network (3G/4G)
    pub fn mobile() -> Self {
        Self {
            packet_loss: 0.02,
            latency_ms: 150,
            jitter_ms: 50,
            bandwidth_bps: 1_000_000, // 1 Mbps
            reorder_probability: 0.01,
            max_reorder_distance: 3,
            duplicate_probability: 0.001,
        }
    }

    /// Poor network conditions
    pub fn poor() -> Self {
        Self {
            packet_loss: 0.10,
            latency_ms: 500,
            jitter_ms: 200,
            bandwidth_bps: 56_000, // 56 kbps
            reorder_probability: 0.05,
            max_reorder_distance: 5,
            duplicate_probability: 0.02,
        }
    }

    /// Satellite internet conditions
    pub fn satellite() -> Self {
        Self {
            packet_loss: 0.01,
            latency_ms: 600,
            jitter_ms: 100,
            bandwidth_bps: 10_000_000, // 10 Mbps
            reorder_probability: 0.02,
            max_reorder_distance: 4,
            duplicate_probability: 0.005,
        }
    }
}

#[derive(Debug)]
struct PacketInfo {
    data: Vec<u8>,
    delivery_time: Instant,
    sequence: u64,
}

pub struct NetworkSimulator {
    conditions: Arc<Mutex<NetworkConditions>>,
    packet_queue: Arc<Mutex<VecDeque<PacketInfo>>>,
    sequence_counter: Arc<Mutex<u64>>,
    bandwidth_tracker: Arc<Mutex<BandwidthTracker>>,
}

#[derive(Debug)]
struct BandwidthTracker {
    last_send_time: Instant,
    bytes_sent: u64,
}

impl NetworkSimulator {
    pub fn new(conditions: NetworkConditions) -> Self {
        Self {
            conditions: Arc::new(Mutex::new(conditions)),
            packet_queue: Arc::new(Mutex::new(VecDeque::new())),
            sequence_counter: Arc::new(Mutex::new(0)),
            bandwidth_tracker: Arc::new(Mutex::new(BandwidthTracker {
                last_send_time: Instant::now(),
                bytes_sent: 0,
            })),
        }
    }

    pub async fn update_conditions(&self, conditions: NetworkConditions) {
        *self.conditions.lock().await = conditions;
    }

    pub async fn simulate_send(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let conditions = self.conditions.lock().await.clone();

        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::from_entropy();

        // Packet loss
        if rng.gen::<f64>() < conditions.packet_loss {
            return Ok(None);
        }

        // Duplicate packet
        let packets = if rng.gen::<f64>() < conditions.duplicate_probability {
            vec![data.clone(), data]
        } else {
            vec![data]
        };

        let mut result_packets = Vec::new();

        for packet_data in packets {
            // Calculate latency
            let base_latency = Duration::from_millis(conditions.latency_ms);
            let jitter = if conditions.jitter_ms > 0 {
                let jitter_range = conditions.jitter_ms as i64;
                let jitter_value = rng.gen_range(-jitter_range..=jitter_range);
                Duration::from_millis(jitter_value.unsigned_abs())
            } else {
                Duration::ZERO
            };
            let total_latency = base_latency + jitter;

            // Bandwidth limiting
            if conditions.bandwidth_bps > 0 {
                let mut tracker = self.bandwidth_tracker.lock().await;
                let elapsed = tracker.last_send_time.elapsed();
                let allowed_bytes =
                    (conditions.bandwidth_bps as f64 * elapsed.as_secs_f64()) as u64;

                if tracker.bytes_sent >= allowed_bytes {
                    let wait_time = Duration::from_secs_f64(
                        (packet_data.len() as f64) / (conditions.bandwidth_bps as f64),
                    );
                    tokio::time::sleep(wait_time).await;
                    tracker.last_send_time = Instant::now();
                    tracker.bytes_sent = packet_data.len() as u64;
                } else {
                    tracker.bytes_sent += packet_data.len() as u64;
                }
            }

            let sequence = {
                let mut seq = self.sequence_counter.lock().await;
                let current = *seq;
                *seq += 1;
                current
            };

            let packet_info = PacketInfo {
                data: packet_data,
                delivery_time: Instant::now() + total_latency,
                sequence,
            };

            // Handle reordering
            if rng.gen::<f64>() < conditions.reorder_probability {
                let reorder_distance = rng.gen_range(1..=conditions.max_reorder_distance);
                let reorder_delay =
                    Duration::from_millis((reorder_distance as u64) * conditions.latency_ms / 4);
                let mut queue = self.packet_queue.lock().await;
                let insert_pos = queue
                    .iter()
                    .position(|p| p.delivery_time > packet_info.delivery_time + reorder_delay)
                    .unwrap_or(queue.len());
                queue.insert(insert_pos, packet_info);
            } else {
                self.packet_queue.lock().await.push_back(packet_info);
            }
        }

        // Process ready packets
        let now = Instant::now();
        let mut queue = self.packet_queue.lock().await;
        while let Some(packet) = queue.front() {
            if packet.delivery_time <= now {
                if let Some(packet) = queue.pop_front() {
                    result_packets.push(packet.data);
                }
            } else {
                break;
            }
        }

        Ok(result_packets.into_iter().next())
    }

    pub async fn flush_pending(&self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut queue = self.packet_queue.lock().await;
        while let Some(packet) = queue.pop_front() {
            packets.push(packet.data);
        }
        packets
    }
}

#[async_trait]
pub trait NetworkProxy: Send + Sync {
    async fn forward(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>>;
}

#[async_trait]
impl NetworkProxy for NetworkSimulator {
    async fn forward(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.simulate_send(data).await
    }
}
