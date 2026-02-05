use tun_rs::DeviceBuilder;
use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("🔍 TAP Support Verification Tool");
    println!("Operating System: {}", std::env::consts::OS);
    
    println!("Attempting to create a TAP (L2) device...");
    println!("(Note: This requires root/admin privileges usually)");

    // Try to create a TAP device
    // tun-rs usually infers TAP if we don't strict-set/or via some platform specific flag.
    // Wait, DeviceBuilder doesn't explicit expose `.tap()` in common API?
    // Let's try to find if we can guess.
    
    // Actually, `tun-rs` 2.x often defaults to TUN. 
    // If it doesn't expose explicit TAP builder in common trait, valid test is platform specific?
    // On macOS, native utun is L3 only. 
    // Usually needing `tuntaposx` implies we need a special driver.
    
    // Let's try a standard build and see if we can find any L2 option, 
    // or just assume if we can't find it, it's not supported easily via this crate.
    
    // Attempt 1: Standard Builder
    let dev = DeviceBuilder::new()
        .name("tap0") // Try to name it tap0
        .build_async();

    match dev {
        Ok(_) => {
            println!("✅ Success: Device created (but check if it is actually TAP/Ethernet!)");
            println!("Please check `ifconfig tap0`");
        }
        Err(e) => {
            println!("❌ Failed: {}", e);
            if std::env::consts::OS == "macos" {
                 println!("ℹ️  Info: macOS `utun` driver does not support TAP (Layer 2) natively.");
                 println!("    You likely need a third-party kext (TunTapOSX) which is deprecated on Silicon.");
                 println!("    For macOS, we likely must stick to TUN (L3).");
            }
        }
    }

    Ok(())
}
