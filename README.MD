A simple tool to pack dotnet apps into a rust clr host using `rustclr`. 

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

### How it works

Very simple build script to encrypt the dot binary.

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

main.rs
```rust
// Include the encrypted dotnet binary
let buffer = include_bytes!("encr");
```


### Recommended Binaries
This list of dotnet bins have been tested and work great.
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/tree/master/dotnet%20v4.8.1%20compiled%20binaries

---


### References 

https://github.com/joaoviictorti/rustclr

https://github.com/trickster0/OffensiveRust

