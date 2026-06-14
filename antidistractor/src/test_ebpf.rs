mod ebpf;

use std::error::Error;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- Antidistractor eBPF Integration Test ---");

    // 1. Load eBPF
    println!("[1/4] Loading eBPF program on wlp1s0...");
    let mut manager = match ebpf::EbpfManager::load(&["wlp1s0"]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: Could not load eBPF (Are you root?): {}", e);
            return Ok(());
        }
    };
    println!("   - Success!");

    // 2. Add domain
    let domain = "www.bilibili.com";
    println!("[2/4] Adding domain '{}' to BLOCKLIST map...", domain);
    manager.add_domain(domain)?;
    println!("   - Added!");

    // 3. Test blocking
    println!("[3/4] Testing blocking (sending curl)...");
    println!("      (This should hang/time out if blocking works)");

    let output = Command::new("curl")
        .args(["-I", "-s", "--connect-timeout", "5", "https://www.bilibili.com"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("   - FAILED: Domain was NOT blocked (got HTTP response).");
        }
        _ => {
            println!("   - SUCCESS: Domain is correctly blocked (connection failed/timed out).");
        }
    }

    // 4. Remove domain and verify recovery
    println!("[4/4] Removing domain and verifying recovery...");
    manager.remove_domain(domain)?;

    let output = Command::new("curl")
        .args(["-I", "-s", "--connect-timeout", "5", "https://www.bilibili.com"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("   - SUCCESS: Domain is accessible again.");
        }
        _ => {
            println!("   - FAILED: Domain is still blocked after removal.");
        }
    }

    println!("--- Test Complete ---");
    Ok(())
}
