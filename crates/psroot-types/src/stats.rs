use serde::{Deserialize, Serialize};

/// Container resource usage statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerStats {
    pub memory_usage: u64,
    pub cpu_user_time: u64,
    pub cpu_kernel_time: u64,
    pub process_count: u32,
    pub total_processes: u32,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
}
