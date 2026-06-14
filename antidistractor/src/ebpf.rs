use aya::{
    maps::HashMap,
    programs::{tc, TcAttachType},
    Ebpf, EbpfLoader,
};
use log::{info, warn};
use std::convert::{TryFrom, TryInto};

const MAX_DNS_NAME_LEN: usize = 256;

pub struct EbpfManager {
    pub bpf: Ebpf,
}

impl EbpfManager {
    pub fn load(ifaces: &[&str]) -> anyhow::Result<Self> {
        if ifaces.is_empty() {
            return Err(anyhow::anyhow!("No interfaces specified"));
        }

        #[cfg(debug_assertions)]
        let data: &[u8] = include_bytes!("../../target/bpfel-unknown-none/debug/antidistractor-ebpf");

        #[cfg(not(debug_assertions))]
        let data: &[u8] = include_bytes!("../../target/bpfel-unknown-none/release/antidistractor-ebpf");

        let mut bpf = EbpfLoader::new()
            .btf(None)
            .load(data)?;

        let mut maybe_program = bpf.program_mut("antidistractor");
        if maybe_program.is_none() {
            maybe_program = bpf.program_mut("classifier");
        }

        let program: &mut tc::SchedClassifier = maybe_program
            .ok_or_else(|| anyhow::anyhow!("Could not find eBPF program 'antidistractor' or 'classifier'"))?
            .try_into()?;

        program.load()?;

        // Attach to all specified interfaces
        let mut attached_count = 0;
        for iface in ifaces {
            // Add clsact qdisc if not already present (required for TC BPF attachment).
            // Ignore errors — the qdisc may already exist (EEXIST / "Exclusivity flag").
            let _ = tc::qdisc_add_clsact(iface);

            // Detach any existing program with our name (ignore errors)
            let _ = tc::qdisc_detach_program(iface, TcAttachType::Egress, "antidistractor");

            match program.attach(iface, TcAttachType::Egress) {
                Ok(_) => {
                    info!("Attached eBPF to interface: {}", iface);
                    attached_count += 1;
                }
                Err(e) => {
                    warn!("Failed to attach eBPF to interface '{}': {}", iface, e);
                }
            }
        }

        if attached_count == 0 {
            return Err(anyhow::anyhow!("Failed to attach eBPF to any interface"));
        }

        Ok(Self { bpf })
    }

    /// Attach eBPF program to an additional interface at runtime (e.g. when a TUN appears later).
    pub fn attach_interface(&mut self, iface: &str) -> anyhow::Result<()> {
        let mut maybe_program = self.bpf.program_mut("antidistractor");
        if maybe_program.is_none() {
            maybe_program = self.bpf.program_mut("classifier");
        }

        let program: &mut tc::SchedClassifier = maybe_program
            .ok_or_else(|| anyhow::anyhow!("Could not find eBPF program"))?
            .try_into()?;

        let _ = tc::qdisc_add_clsact(iface);
        let _ = tc::qdisc_detach_program(iface, TcAttachType::Egress, "antidistractor");

        program.attach(iface, TcAttachType::Egress)
            .map_err(|e| anyhow::anyhow!("Failed to attach TC program to '{}': {}", iface, e))?;

        info!("Attached eBPF to interface: {}", iface);
        Ok(())
    }

    pub fn add_domain(&mut self, domain: &str) -> anyhow::Result<()> {
        let mut blocklist: HashMap<_, [u8; MAX_DNS_NAME_LEN], u8> = HashMap::try_from(
            self.bpf.map_mut("BLOCKLIST").ok_or_else(|| anyhow::anyhow!("Map BLOCKLIST not found"))?
        )?;
        let mut name = [0u8; MAX_DNS_NAME_LEN];
        let bytes = domain.as_bytes();
        let len = bytes.len().min(MAX_DNS_NAME_LEN);
        name[..len].copy_from_slice(&bytes[..len]);
        blocklist.insert(name, 1, 0)?;
        Ok(())
    }

    pub fn remove_domain(&mut self, domain: &str) -> anyhow::Result<()> {
        let mut blocklist: HashMap<_, [u8; MAX_DNS_NAME_LEN], u8> = HashMap::try_from(
            self.bpf.map_mut("BLOCKLIST").ok_or_else(|| anyhow::anyhow!("Map BLOCKLIST not found"))?
        )?;
        let mut name = [0u8; MAX_DNS_NAME_LEN];
        let bytes = domain.as_bytes();
        let len = bytes.len().min(MAX_DNS_NAME_LEN);
        name[..len].copy_from_slice(&bytes[..len]);
        blocklist.remove(&name)?;
        Ok(())
    }
}
