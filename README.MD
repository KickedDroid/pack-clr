# Pack-CLR
A tool to pack dotnet apps into a rust clr host using `clroxide`. Utilizing hardware breakpoints for patchless amsi bypass.

TODO: 
- remove rc4 encryption
- Add obfuscation on build

---
Preq
```
rustup target add x86_64-pc-windows-gnu
```

## Usage 

Building

```
./pack <dotnet exe path>
```

Run the packed exe.

```
C:\> .\packed.exe <Executable Args>
```

---

Example usage with SharpHound.exe

On your local machine pack SharpHound into the clrhost.
```
.\pack SharpHound.exe
```

Rename the binary if you want to.
```
mv packed.exe SharpHound-p.exe
```

On the target machine, use the same args you would with the dotnet app.

```
.\SharpHound-p.exe -c All --zipfilename example
```


---

### Build Encryption

Very simple build script to encrypt the dotnet binary.

build.rs
```rust
// Create the key 
    let key = generate_random_string(256);

    // ...
// Encrypt the payload
    let file = fs::read("src/unencrypted").unwrap();
    let mut cipher = crypto::rc4::Rc4::new(key.as_bytes());
    let mut o = file.clone();
    cipher.process(&file[..], &mut o);
    let _ = fs::write("src/encr", o);
```
---

### AMSI Bypass

Utilizing the repo https://github.com/imunproductive/hwbp for hardware breakpoints. Learn 
more about this technique here https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/

---

### Recommended Binaries
This list of dotnet bins have been tested and work great.
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/tree/master/dotnet%20v4.8.1%20compiled%20binaries

---


### References
Thanks given to
- https://github.com/yamakadi/clroxide
- https://github.com/joaoviictorti/rustclr
- https://github.com/trickster0/OffensiveRust

