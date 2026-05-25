use aya::{
    maps::HashMap,
    programs::{tc, TcAttachType},
    Ebpf, EbpfLoader,
};
use std::convert::{TryFrom, TryInto};

const MAX_DNS_NAME_LEN: usize = 256;

pub struct EbpfManager {
    pub bpf: Ebpf,
}

impl EbpfManager {
    pub fn load(iface: &str) -> anyhow::Result<Self> {
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
        
        // Add clsact qdisc if not already present (required for TC BPF attachment).
        // Ignore errors — the qdisc may already exist (EEXIST / "Exclusivity flag").
        let _ = tc::qdisc_add_clsact(iface);

        // Detach any existing program with our name (ignore errors)
        let _ = tc::qdisc_detach_program(iface, TcAttachType::Egress, "antidistractor");

        program.attach(iface, TcAttachType::Egress)
            .map_err(|e| anyhow::anyhow!("Failed to attach TC program: {}", e))?;

        Ok(Self { bpf })
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
