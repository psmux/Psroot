//! Job Object accounting and statistics queries.

use crate::handle::JobObject;
use psroot_types::error::Result;
use psroot_types::stats::ContainerStats;
use windows_sys::Win32::System::JobObjects::*;

/// Raw accounting info (48 bytes on x64).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct BasicAccountingInfo {
    pub total_user_time: i64,
    pub total_kernel_time: i64,
    pub this_period_user_time: i64,
    pub this_period_kernel_time: i64,
    pub total_page_fault_count: u32,
    pub total_processes: u32,
    pub active_processes: u32,
    pub total_terminated_processes: u32,
}

/// IO_COUNTERS (48 bytes).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct IoCounters {
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

/// Combined accounting + IO (96 bytes).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct BasicAndIoAccountingInfo {
    pub basic: BasicAccountingInfo,
    pub io: IoCounters,
}

impl JobObject {
    /// Query resource usage statistics.
    pub fn query_stats(&self) -> Result<ContainerStats> {
        let acct: BasicAndIoAccountingInfo =
            self.query_info(JobObjectBasicAndIoAccountingInformation)?;

        // Query extended info for peak memory
        let ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            self.query_info(JobObjectExtendedLimitInformation)?;

        Ok(ContainerStats {
            cpu_user_time: acct.basic.total_user_time as u64,
            cpu_kernel_time: acct.basic.total_kernel_time as u64,
            process_count: acct.basic.active_processes,
            total_processes: acct.basic.total_processes,
            memory_usage: ext.PeakJobMemoryUsed as u64,
            io_read_bytes: acct.io.read_transfer_count,
            io_write_bytes: acct.io.write_transfer_count,
        })
    }
}
