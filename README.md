# Warden Export

A DLL injection tool for World of Warcraft that dumps and reconstructs the Warden module into a proper PE file format.

## 🎯 Overview

Warden Export is a research tool designed to extract and analyze the Warden anti-cheat module used in World of Warcraft. It intercepts the Warden module during runtime, dumps it from memory, and reconstructs a valid PE (Portable Executable) file with proper headers, sections, and import tables.

## ✨ Features

- **Memory Dumping**: Captures the Warden module from process memory
- **PE Reconstruction**: Rebuilds a valid PE file with proper:
  - DOS/NT headers
  - Section headers and data
  - Import Address Table (IAT)
  - Import directory
- **Import Resolution**: Automatically resolves and patches import addresses
- **SHA-256 Hashing**: Generates cryptographic hash of dumped module
- **Colorized Console**: Beautiful color-coded output for easy debugging

## 🚀 Usage

1. **Build the DLL**:
   - Open the project in Visual Studio
   - Build in Release/Debug mode
   - Output: `WardenExport.dll`

2. **Inject the DLL**:
   - Use your preferred DLL injector
   - Inject into the WoW process (e.g., `Wow.exe`)
   - The tool will automatically hook and dump Warden when loaded

3. **Output**:
   - A debug console will appear showing the dump process
   - Dumped PE file will be saved to: `C:\warden_dumped.exe`

## 📋 Requirements

- Windows 10/11
- Visual Studio 2019+ (for building)
- DLL injector (for runtime injection)
- World of Warcraft client

## 🛠️ Technical Details

### Hook Implementation
- Detours the Warden initialization routine
- Captures module base address and size
- Reconstructs PE headers and sections
- Patches IAT with resolved imports

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. It is designed to help security researchers understand anti-cheat systems and PE file formats. 

**Usage of this tool may violate the Terms of Service of World of Warcraft.** Use at your own risk. The author is not responsible for any consequences including but not limited to account bans or legal action.

## 📝 License

This project is provided as-is for educational purposes.

## 👤 Author

**TechMecca**
- GitHub: [https://github.com/TechMecca](https://github.com/TechMecca)
- Discord: [https://discord.gg/qwXEEZ4whU](https://discord.gg/qwXEEZ4whU)

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

---

**Note**: This is a research tool. Always respect software licenses and terms of service.
