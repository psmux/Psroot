//! Resource limit configuration for Job Objects.

use crate::handle::JobObject;
use psroot_types::config::ResourceLimits;
use psroot_types::error::Result;
use tracing::debug;
use windows_sys::Win32::System::JobObjects::*;

// Limit flags
const KILL_ON_JOB_CLOSE: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
const LIMIT_JOB_MEMORY: u32 = JOB_OBJECT_LIMIT_JOB_MEMORY;
const LIMIT_ACTIVE_PROCESS: u32 = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
const LIMIT_AFFINITY: u32 = JOB_OBJECT_LIMIT_AFFINITY;
const LIMIT_PRIORITY_CLASS: u32 = JOB_OBJECT_LIMIT_PRIORITY_CLASS;

/// Create a zeroed JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
fn zeroed_ext_limit() -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    unsafe { std::mem::zeroed() }
}

/// Create a zeroed JOBOBJECT_CPU_RATE_CONTROL_INFORMATION.
fn zeroed_cpu_rate() -> JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
    unsafe { std::mem::zeroed() }
}

impl JobObject {
    /// Enable kill-on-close: all processes die when this handle is dropped.
    pub fn enable_kill_on_close(&self) -> Result<()> {
        let mut info = zeroed_ext_limit();
        info.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE;
        self.set_info(JobObjectExtendedLimitInformation, &info)?;
        debug!("Kill-on-close enabled");
        Ok(())
    }

    /// Apply a full ResourceLimits configuration.
    pub fn apply_limits(&self, limits: &ResourceLimits) -> Result<()> {
        let mut info = zeroed_ext_limit();
        let mut flags = KILL_ON_JOB_CLOSE;

        // Memory
        if limits.memory > 0 {
            flags |= LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = limits.memory as usize;
            debug!(bytes = limits.memory, "Memory limit set");
        }

        // Process count
        if limits.max_processes > 0 {
            flags |= LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = limits.max_processes;
            debug!(max = limits.max_processes, "Process limit set");
        }

        // Affinity
        if limits.affinity > 0 {
            flags |= LIMIT_AFFINITY;
            info.BasicLimitInformation.Affinity = limits.affinity as usize;
        }

        // Priority class
        if limits.priority_class > 0 {
            flags |= LIMIT_PRIORITY_CLASS;
            info.BasicLimitInformation.PriorityClass = limits.priority_class;
        }

        info.BasicLimitInformation.LimitFlags = flags;
        self.set_info(JobObjectExtendedLimitInformation, &info)?;

        // CPU rate (separate call — different info class)
        if limits.cpu_rate > 0 && limits.cpu_rate < 10_000 {
            self.set_cpu_rate(limits.cpu_rate)?;
        }

        Ok(())
    }

    /// Set CPU rate as hard cap. 1–10000 (0.01%–100%).
    pub fn set_cpu_rate(&self, rate: u32) -> Result<()> {
        let mut info = zeroed_cpu_rate();
        info.ControlFlags =
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        info.Anonymous.CpuRate = rate;
        self.set_info(JobObjectCpuRateControlInformation, &info)?;
        debug!(rate, "CPU rate set");
        Ok(())
    }

    /// Set memory limit in bytes.
    pub fn set_memory_limit(&self, bytes: u64) -> Result<()> {
        let mut info = zeroed_ext_limit();
        info.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE | LIMIT_JOB_MEMORY;
        info.JobMemoryLimit = bytes as usize;
        self.set_info(JobObjectExtendedLimitInformation, &info)
    }

    /// Set maximum active processes.
    pub fn set_process_limit(&self, max: u32) -> Result<()> {
        let mut info = zeroed_ext_limit();
        info.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE | LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = max;
        self.set_info(JobObjectExtendedLimitInformation, &info)
    }
}


