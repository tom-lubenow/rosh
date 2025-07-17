use anyhow::Result;
use similar::{ChangeTag, TextDiff};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct TerminalCapture {
    lines: Arc<Mutex<Vec<String>>>,
    raw_output: Arc<Mutex<Vec<u8>>>,
}

impl Default for TerminalCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalCapture {
    pub fn new() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
            raw_output: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn capture_bytes(&self, data: &[u8]) {
        self.raw_output.lock().await.extend_from_slice(data);

        // Parse into lines
        if let Ok(text) = std::str::from_utf8(data) {
            let stripped = strip_ansi_escapes::strip(text);
            if let Ok(clean_text) = String::from_utf8(stripped) {
                let mut lines = self.lines.lock().await;
                for line in clean_text.lines() {
                    lines.push(line.to_string());
                }
            }
        }
    }

    pub async fn get_lines(&self) -> Vec<String> {
        self.lines.lock().await.clone()
    }

    pub async fn get_raw_output(&self) -> Vec<u8> {
        self.raw_output.lock().await.clone()
    }

    pub async fn clear(&self) {
        self.lines.lock().await.clear();
        self.raw_output.lock().await.clear();
    }

    pub async fn wait_for_line(
        &self,
        pattern: &str,
        timeout: std::time::Duration,
    ) -> Result<String> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let lines = self.lines.lock().await;
            for line in lines.iter() {
                if line.contains(pattern) {
                    return Ok(line.clone());
                }
            }
            drop(lines);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        anyhow::bail!("Timeout waiting for line containing: {}", pattern)
    }

    pub async fn wait_for_regex(
        &self,
        regex: &regex::Regex,
        timeout: std::time::Duration,
    ) -> Result<String> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let lines = self.lines.lock().await;
            for line in lines.iter() {
                if regex.is_match(line) {
                    return Ok(line.clone());
                }
            }
            drop(lines);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        anyhow::bail!("Timeout waiting for regex: {}", regex)
    }
}

pub struct TerminalComparator;

impl Default for TerminalComparator {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalComparator {
    pub fn new() -> Self {
        Self
    }

    pub fn compare_output(&self, expected: &str, actual: &str) -> Result<()> {
        let expected_clean = self.normalize_output(expected);
        let actual_clean = self.normalize_output(actual);

        if expected_clean == actual_clean {
            return Ok(());
        }

        // Generate diff for debugging
        let diff = TextDiff::from_lines(&expected_clean, &actual_clean);
        let mut diff_output = String::new();

        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                ChangeTag::Delete => "-",
                ChangeTag::Insert => "+",
                ChangeTag::Equal => " ",
            };
            diff_output.push_str(&format!("{sign}{change}"));
        }

        anyhow::bail!(
            "Terminal output mismatch:\n\nExpected:\n{}\n\nActual:\n{}\n\nDiff:\n{}",
            expected_clean,
            actual_clean,
            diff_output
        )
    }

    pub fn compare_lines(&self, expected: &[String], actual: &[String]) -> Result<()> {
        if expected.len() != actual.len() {
            anyhow::bail!(
                "Line count mismatch: expected {} lines, got {} lines",
                expected.len(),
                actual.len()
            );
        }

        for (i, (exp_line, act_line)) in expected.iter().zip(actual.iter()).enumerate() {
            let exp_clean = self.normalize_line(exp_line);
            let act_clean = self.normalize_line(act_line);

            if exp_clean != act_clean {
                anyhow::bail!(
                    "Line {} mismatch:\nExpected: {}\nActual: {}",
                    i + 1,
                    exp_clean,
                    act_clean
                );
            }
        }

        Ok(())
    }

    fn normalize_output(&self, output: &str) -> String {
        output
            .lines()
            .map(|line| self.normalize_line(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn normalize_line(&self, line: &str) -> String {
        // Strip ANSI escape codes
        let stripped = strip_ansi_escapes::strip(line);
        let clean = String::from_utf8_lossy(&stripped);

        // Normalize whitespace
        clean.trim_end().to_string()
    }

    pub fn assert_contains(&self, haystack: &str, needle: &str) -> Result<()> {
        let haystack_clean = self.normalize_output(haystack);
        let needle_clean = self.normalize_output(needle);

        if !haystack_clean.contains(&needle_clean) {
            anyhow::bail!(
                "Output does not contain expected text:\nExpected to find:\n{}\n\nIn output:\n{}",
                needle_clean,
                haystack_clean
            );
        }

        Ok(())
    }

    pub fn assert_not_contains(&self, haystack: &str, needle: &str) -> Result<()> {
        let haystack_clean = self.normalize_output(haystack);
        let needle_clean = self.normalize_output(needle);

        if haystack_clean.contains(&needle_clean) {
            anyhow::bail!(
                "Output contains unexpected text:\nDid not expect to find:\n{}\n\nIn output:\n{}",
                needle_clean,
                haystack_clean
            );
        }

        Ok(())
    }
}
