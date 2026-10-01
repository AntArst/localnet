use anyhow::{anyhow, Result};
use rand::random;
use serde::{Deserialize, Serialize};
use statime::config::{
    AcceptableMasterList, ClockIdentity, DelayMechanism, InstanceConfig, PortConfig,
    PtpMinorVersion, TimePropertiesDS, TimeSource,
};
use statime::time::{Duration, Interval, Time};
use statime::Clock;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClockDiscipline {
    FreeRunning,
    FrequencyLocked,
    PhaseLocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClockSnapshot {
    pub local_time_ns: u64,
    pub reference_time_ns: u64,
    pub offset_ns: i64,
    pub frequency_ppm: f64,
    pub discipline: ClockDiscipline,
}

impl ClockSnapshot {
    pub fn from_time(local_time: Time, offset: Duration, frequency_ppm: f64, discipline: ClockDiscipline) -> Self {
        let local_time_ns = saturating_u64(local_time);
        let offset_ns = saturating_i64(offset);
        let reference_time_ns = if offset_ns >= 0 {
            local_time_ns.saturating_add(offset_ns as u64)
        } else {
            local_time_ns.saturating_sub(offset_ns.unsigned_abs())
        };

        Self {
            local_time_ns,
            reference_time_ns,
            offset_ns,
            frequency_ppm,
            discipline,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PtpClockConfig {
    pub instance: InstanceConfig,
    pub time_properties: TimePropertiesDS,
    pub port: PortConfig<AcceptAllMasters>,
}

impl PtpClockConfig {
    pub fn default_profile() -> Self {
        Self {
            instance: default_instance_config(),
            time_properties: default_time_properties(),
            port: default_port_config(),
        }
    }

    pub fn lan_profile() -> Self {
        let mut profile = Self::default_profile();
        profile.port.announce_interval = Interval::from_log_2(0);
        profile.port.sync_interval = Interval::from_log_2(-3);
        profile.port.delay_mechanism = DelayMechanism::E2E {
            interval: Interval::from_log_2(-3),
        };
        profile
    }

    pub fn set_priority(&mut self, priority: u8) {
        self.instance.priority_1 = priority;
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllMasters;

impl AcceptableMasterList for AcceptAllMasters {
    fn is_acceptable(&self, _identity: ClockIdentity) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct PtpPortProfile {
    pub config: PtpClockConfig,
    pub bind_interval: Interval,
}

impl Default for PtpPortProfile {
    fn default() -> Self {
        Self {
            config: PtpClockConfig::lan_profile(),
            bind_interval: Interval::from_log_2(-3),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SoftwareClock {
    inner: Arc<Mutex<SoftwareClockState>>,
}

#[derive(Debug)]
struct SoftwareClockState {
    epoch: Time,
    offset: Duration,
    frequency_ratio: f64,
    properties: TimePropertiesDS,
    started_at: Instant,
}

impl SoftwareClock {
    pub fn new(epoch: Time, properties: TimePropertiesDS) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SoftwareClockState {
                epoch,
                offset: Duration::ZERO,
                frequency_ratio: 1.0,
                properties,
                started_at: Instant::now(),
            })),
        }
    }

    pub fn new_unix() -> Self {
        let system_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let epoch = Time::from_secs(system_now.as_secs()) 
            + Duration::from_nanos(system_now.subsec_nanos() as i64);
        Self::new(epoch, default_time_properties())
    }

    pub fn snapshot(&self, discipline: ClockDiscipline) -> ClockSnapshot {
        let state = self.inner.lock().expect("software clock lock poisoned");
        let now = state.now();
        ClockSnapshot::from_time(
            now,
            state.offset,
            (state.frequency_ratio - 1.0) * 1_000_000.0,
            discipline,
        )
    }

    pub fn time_properties(&self) -> TimePropertiesDS {
        self.inner
            .lock()
            .expect("software clock lock poisoned")
            .properties
    }

    pub fn current_time(&self) -> Time {
        self.inner
            .lock()
            .expect("software clock lock poisoned")
            .now()
    }
}

impl Default for SoftwareClock {
    fn default() -> Self {
        Self::new_unix()
    }
}

impl Clock for SoftwareClock {
    type Error = anyhow::Error;

    fn now(&self) -> Time {
        self.inner
            .lock()
            .expect("software clock lock poisoned")
            .now()
    }

    fn step_clock(&mut self, offset: Duration) -> Result<Time, Self::Error> {
        let mut state = self.inner.lock().map_err(|_| anyhow!("software clock lock poisoned"))?;
        state.offset += offset;
        Ok(state.now())
    }

    fn set_frequency(&mut self, ppm: f64) -> Result<Time, Self::Error> {
        let mut state = self.inner.lock().map_err(|_| anyhow!("software clock lock poisoned"))?;
        state.frequency_ratio = 1.0 + (ppm / 1_000_000.0);
        Ok(state.now())
    }

    fn set_properties(&mut self, properties: &TimePropertiesDS) -> Result<(), Self::Error> {
        let mut state = self.inner.lock().map_err(|_| anyhow!("software clock lock poisoned"))?;
        state.properties = *properties;
        Ok(())
    }
}

impl SoftwareClockState {
    fn now(&self) -> Time {
        let elapsed_ns = self.started_at.elapsed().as_nanos() as f64;
        let disciplined_elapsed_ns = (elapsed_ns * self.frequency_ratio).max(0.0).round();
        self.epoch + Duration::from_nanos(disciplined_elapsed_ns as i64) + self.offset
    }
}

pub fn default_instance_config() -> InstanceConfig {
    InstanceConfig {
        clock_identity: random_clock_identity(),
        priority_1: 128,
        priority_2: 128,
        domain_number: 0,
        slave_only: false,
        sdo_id: Default::default(),
        path_trace: false,
    }
}

fn random_clock_identity() -> ClockIdentity {
    let mut mac = random::<[u8; 6]>();
    mac[0] |= 0x02;
    mac[0] &= 0xfe;
    ClockIdentity::from_mac_address(mac)
}

pub fn default_time_properties() -> TimePropertiesDS {
    TimePropertiesDS::new_arbitrary_time(false, false, TimeSource::InternalOscillator)
}

pub fn default_port_config() -> PortConfig<AcceptAllMasters> {
    PortConfig {
        acceptable_master_list: AcceptAllMasters,
        delay_mechanism: DelayMechanism::E2E {
            interval: Interval::from_log_2(-2),
        },
        announce_interval: Interval::from_log_2(0),
        announce_receipt_timeout: 3,
        sync_interval: Interval::from_log_2(-2),
        master_only: false,
        delay_asymmetry: Duration::ZERO,
        minor_ptp_version: PtpMinorVersion::One,
    }
}

fn saturating_u64(time: Time) -> u64 {
    let seconds = time.secs();
    let subsec_nanos = time.subsec_nanos() as u64;
    seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(subsec_nanos)
}

fn saturating_i64(duration: Duration) -> i64 {
    let nanos = duration.nanos_rounded();
    nanos.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}