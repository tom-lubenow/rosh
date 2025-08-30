use rosh_network::protocol::MessageStats;

#[test]
fn update_rtt_sets_value_when_now_after_sent() {
    let mut stats = MessageStats::default();
    // Choose a timestamp in the past: now - 10ms (10000 microseconds)
    let now = rosh_network::protocol::Message::timestamp_now();
    let past = now.saturating_sub(10_000);
    stats.update_rtt(past);
    assert!(stats.last_rtt_micros.is_some());
}
