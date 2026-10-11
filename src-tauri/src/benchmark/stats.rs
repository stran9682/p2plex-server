use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub category: String,
    pub scenario: String,
    pub scale: usize,
    pub iterations: usize,
    pub min_us: f64,
    pub max_us: f64,
    pub mean_us: f64,
    pub median_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub std_dev_us: f64,
    pub ops_per_sec: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_samples_us: Vec<f64>,
}

impl BenchmarkResult {
    pub fn compute(
        category: &str,
        scenario: &str,
        scale: usize,
        mut samples_us: Vec<f64>,
    ) -> Self {
        let raw_samples = samples_us.clone();
        samples_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let count = samples_us.len();
        if count == 0 {
            return Self {
                category: category.to_string(),
                scenario: scenario.to_string(),
                scale,
                iterations: 0,
                min_us: 0.0,
                max_us: 0.0,
                mean_us: 0.0,
                median_us: 0.0,
                p95_us: 0.0,
                p99_us: 0.0,
                std_dev_us: 0.0,
                ops_per_sec: 0.0,
                raw_samples_us: Vec::new(),
            };
        }

        let sum: f64 = samples_us.iter().sum();
        let mean = sum / (count as f64);
        let min = samples_us[0];
        let max = samples_us[count - 1];
        let median = samples_us[count / 2];
        let p95 = samples_us[((count as f64 * 0.95).floor() as usize).min(count - 1)];
        let p99 = samples_us[((count as f64 * 0.99).floor() as usize).min(count - 1)];

        let variance = samples_us
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / (count as f64);
        let std_dev = variance.sqrt();
        let ops_per_sec = if mean > 0.0 {
            1_000_000.0 / mean
        } else {
            0.0
        };

        Self {
            category: category.to_string(),
            scenario: scenario.to_string(),
            scale,
            iterations: count,
            min_us: min,
            max_us: max,
            mean_us: mean,
            median_us: median,
            p95_us: p95,
            p99_us: p99,
            std_dev_us: std_dev,
            ops_per_sec,
            raw_samples_us: raw_samples,
        }
    }
}

pub fn print_result_row(res: &BenchmarkResult) {
    let (p50_str, p95_str, mean_str) = if res.mean_us >= 1000.0 {
        (
            format!("{:>7.2} ms", res.median_us / 1000.0),
            format!("{:>7.2} ms", res.p95_us / 1000.0),
            format!("{:>7.2} ms", res.mean_us / 1000.0),
        )
    } else {
        (
            format!("{:>7.2} µs", res.median_us),
            format!("{:>7.2} µs", res.p95_us),
            format!("{:>7.2} µs", res.mean_us),
        )
    };

    let tps_str = if res.ops_per_sec >= 1000.0 {
        format!("{:>8.1}k ops/s", res.ops_per_sec / 1000.0)
    } else {
        format!("{:>8.0} ops/s", res.ops_per_sec)
    };

    println!(
        "{:<36} [scale={:>4}] | p50: {} | p95: {} | mean: {} | throughput: {}",
        res.scenario, res.scale, p50_str, p95_str, mean_str, tps_str
    );
}

pub fn print_summary_table_markdown(title: &str, results: &[BenchmarkResult]) {
    println!("\n\n### {}\n", title);
    println!("| Category | Scenario | Scale / Peers | Mean Latency | Median (p50) | p95 Latency | p99 Latency | Throughput |");
    println!("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |");

    for r in results {
        let (mean_str, p50_str, p95_str, p99_str) = if r.mean_us >= 1_000.0 {
            (
                format!("{:.2} ms", r.mean_us / 1_000.0),
                format!("{:.2} ms", r.median_us / 1_000.0),
                format!("{:.2} ms", r.p95_us / 1_000.0),
                format!("{:.2} ms", r.p99_us / 1_000.0),
            )
        } else {
            (
                format!("{:.2} µs", r.mean_us),
                format!("{:.2} µs", r.median_us),
                format!("{:.2} µs", r.p95_us),
                format!("{:.2} µs", r.p99_us),
            )
        };

        let tps_str = if r.ops_per_sec >= 1_000.0 {
            format!("{:.1}k ops/s", r.ops_per_sec / 1_000.0)
        } else {
            format!("{:.0} ops/s", r.ops_per_sec)
        };

        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            r.category, r.scenario, r.scale, mean_str, p50_str, p95_str, p99_str, tps_str
        );
    }
    println!();
}

/// Generates a RFC-4180 compliant CSV string of summary benchmark results
pub fn to_csv_summary(results: &[BenchmarkResult]) -> String {
    let mut out = String::from(
        "category,scenario,scale,iterations,min_us,max_us,mean_us,median_us,p95_us,p99_us,std_dev_us,ops_per_sec\n",
    );
    for r in results {
        out.push_str(&format!(
            "\"{}\",\"{}\",{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.2}\n",
            r.category.replace('"', "\"\""),
            r.scenario.replace('"', "\"\""),
            r.scale,
            r.iterations,
            r.min_us,
            r.max_us,
            r.mean_us,
            r.median_us,
            r.p95_us,
            r.p99_us,
            r.std_dev_us,
            r.ops_per_sec,
        ));
    }
    out
}

/// Generates a long-format raw data CSV for post-hoc statistical analysis
/// (e.g. CDFs, boxplots, ANOVA, histograms in Pandas, R, or Excel).
pub fn to_csv_raw(results: &[BenchmarkResult]) -> String {
    let mut out = String::from("category,scenario,scale,iteration,latency_us\n");
    for r in results {
        for (i, sample) in r.raw_samples_us.iter().enumerate() {
            out.push_str(&format!(
                "\"{}\",\"{}\",{},{},{:.4}\n",
                r.category.replace('"', "\"\""),
                r.scenario.replace('"', "\"\""),
                r.scale,
                i + 1,
                sample,
            ));
        }
    }
    out
}

/// Writes summary CSV table directly to disk, creating parent folders if needed
pub fn save_csv_summary<P: AsRef<std::path::Path>>(path: P, results: &[BenchmarkResult]) -> std::io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, to_csv_summary(results))
}

/// Writes long-format raw trial samples directly to disk, creating parent folders if needed
pub fn save_csv_raw<P: AsRef<std::path::Path>>(path: P, results: &[BenchmarkResult]) -> std::io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, to_csv_raw(results))
}

