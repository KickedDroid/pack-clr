A simple tool to pack dotnet apps into a rust clr host. With basic RC4 encryption. 

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



### Recommended Binaries
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/tree/master/dotnet%20v4.8.1%20compiled%20binaries

---


### References 

https://github.com/joaoviictorti/rustclr?tab=readme-ov-file

https://github.com/trickster0/OffensiveRust

