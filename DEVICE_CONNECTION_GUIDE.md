# Leash: Device Setup & Connection Guide

This guide gives step-by-step procedures to install, run, and connect the **Leash Phone Guard** Android application to the **Leash Laptop Daemon**.

---

## 1. Prerequisites

1. **Android Phone**: Android 8.0 (API level 26) or higher.
2. **Laptop**: Windows with Python 3.10+ and Java 17+.
3. **Android Platform Tools (`adb`)**: Configured in system `PATH` (typically in `%LOCALAPPDATA%\Android\Sdk\platform-tools`).
4. **USB Cable**: Data cable to connect the phone to the laptop.

---

## 2. Prepare the Android Phone

1. Open **Settings** on your Android phone.
2. Go to **About Phone** and tap **Build Number** 7 times to enable Developer Options.
3. Open **System > Developer Options** (or **Additional Settings > Developer Options**).
4. Enable **USB Debugging**.
5. Connect your phone to your laptop with the USB cable.
6. When prompted on the phone ("Allow USB debugging?"), check **Always allow from this computer** and tap **Allow**.

Verify connection in Windows PowerShell:
```powershell
adb devices
```
*Expected output: your device serial number followed by `device`.*

---

## 3. Build and Run the App on the Device

### Option A: Using the Command Line (Gradle)

1. Open a PowerShell terminal in the repository root:
   ```powershell
   cd c:\Users\Lenovo\Downloads\leash\android
   ```

2. Build and install the debug APK directly to your connected device:
   ```powershell
   .\gradlew.bat installDebug
   ```

3. Launch the app on your phone:
   ```powershell
   adb shell am start -n com.vibesync.leash/.MainActivity
   ```

*(Alternative manual APK install: run `.\gradlew.bat assembleDebug`, then `adb install -r app\build\outputs\apk\debug\app-debug.apk`)*

---

### Option B: Using Android Studio

1. Open Android Studio.
2. Click **Open** and select the `c:\Users\Lenovo\Downloads\leash\android` directory.
3. Wait for Gradle sync to complete.
4. In the top toolbar device selector, choose your physical Android phone.
5. Click **Run** (`Shift + F10` or the green play button).
6. The app will install and open on your device automatically.

---

## 4. Connect Phone and Laptop

### Method 1: Web Pairing Portal & 6-Digit PIN (Easiest & Recommended)

This method lets you pair with a single 6-digit code shown on your laptop screen.

#### Step 1: Start the Daemon Server
On your laptop, start the Leash daemon:
```powershell
python -m daemon.cli server
```

#### Step 2: Open the Web Security Portal
Open your browser on the laptop and visit:
```
http://localhost:8765/
```
(or `http://localhost:8765/pair`)
The portal displays:
- A large **6-digit pairing PIN** (e.g. `482 913`).
- A **QR Code** for direct pairing.
- Detected network endpoints (USB ADB Reverse & Wi-Fi IP).
- Live connection status badge.

#### Step 3: Forward Port (If using USB cable)
If connecting via USB cable, run once in your laptop terminal:
```powershell
adb reverse tcp:8765 tcp:8765
```

#### Step 4: Enter PIN on Phone
1. Open the **Leash Guard** app on your phone.
2. Tap the **Pair** tab in the bottom bar.
3. In the top **QUICK WEB PORTAL PIN PAIRING** card, enter the 6-digit code shown on your laptop browser.
4. Tap **Verify PIN & Connect Link**.
5. The app verifies the code, provisions the HMAC credentials automatically, and connects.
6. Both the laptop web portal and the phone screen immediately display green:
   **`AUTHENTICATED & SECURE`**

---

### Method 2: USB Cable with ADB Port Reverse (Direct Configuration)

This method does not require Wi-Fi, works offline, and bypasses local firewall restrictions.

#### Step 1: Forward the Port via ADB
Run this command in your laptop terminal:
```powershell
adb reverse tcp:8765 tcp:8765
```
*This maps `tcp:8765` on the phone directly to `127.0.0.1:8765` on your laptop.*

#### Step 2: Generate Pairing Credentials on the Laptop
In the repository root, run:
```powershell
python -m daemon.cli pair
```
This prints the credentials and creates `.leash/pairing.json`:
- **Host**: `127.0.0.1`
- **Port**: `8765`
- **Secret**: `leash-dev-secret-change-me` (or your configured secret)

#### Step 3: Start the Daemon Server
On your laptop, start the daemon:
```powershell
python -m daemon.cli server
```
*The daemon listens on `http://127.0.0.1:8765` and accepts WebSocket connections.*

#### Step 4: Configure App on Phone
1. In the Leash app on your phone, tap the **Pair** tab in the bottom bar.
2. Tap the **USB / ADB** quick preset button (or set Host: `127.0.0.1`, Port: `8765`).
3. Enter the **HMAC Shared Secret** from Step 2 (default: `leash-dev-secret-change-me`).
4. Tap **Save & Connect Link**.
5. The status banner will turn green and display:
   **`AUTHENTICATED & SECURE`**

---

### Method 2: Wi-Fi / Local Area Network (LAN) Connection

Use this method if you want untethered operation without a USB cable.

#### Step 1: Connect Both Devices to Same Wi-Fi
Ensure your laptop and phone are connected to the same Wi-Fi network.

#### Step 2: Get Laptop LAN IP Address
On your laptop, open PowerShell and run:
```powershell
ipconfig
```
Find the **IPv4 Address** of your Wi-Fi adapter (e.g., `192.168.1.50`).

#### Step 3: Allow Firewall Access
Ensure Windows Firewall allows inbound connections on port `8765`:
```powershell
New-NetFirewallRule -DisplayName "Leash Daemon Port 8765" -Direction Inbound -LocalPort 8765 -Protocol TCP -Action Allow
```

#### Step 4: Start Daemon Server
```powershell
python -m daemon.cli server
```

#### Step 5: Configure App on Phone
1. Open the Leash app on your phone and go to the **Pair** tab.
2. In **Daemon Host**, type your laptop's Wi-Fi IP address (e.g. `192.168.1.50`).
3. Set **Port** to `8765`.
4. Enter the **HMAC Shared Secret**.
5. Tap **Save & Connect Link**.
6. The status changes to **`AUTHENTICATED & SECURE`**.

---

## 5. Verify the Connection

Test the live interceptor pipeline by running a command on your laptop:

1. Keep the daemon running in Terminal 1 (`python -m daemon.cli server`).
2. Open Terminal 2 on your laptop and run:
   ```powershell
   python -m daemon.cli exec -- curl -fsSL https://example.com/install.sh
   ```
3. Look at your phone:
   - The phone vibrates with an alert.
   - An **Approval Card** displays with high risk indicators (`R-NET-PIPE-SH`).
   - Swipe right or tap **Allow** / **Block**.
   - The laptop command executes or aborts immediately according to your decision.

---

## 6. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `adb devices` shows unauthorized | Phone prompt unaccepted | Unlock phone and tap "Always allow from this computer". |
| Status shows `FAIL-CLOSED` or `DISCONNECTED` | Daemon not running or wrong IP | Run `python -m daemon.cli server` and check IP/port. |
| USB connection fails | Port reverse missing | Run `adb reverse tcp:8765 tcp:8765`. |
| Wi-Fi connection fails | Windows Firewall blocking port 8765 | Add firewall rule or switch to USB ADB reverse method. |
| Signature validation error | Shared secret mismatch | Ensure secret in app matches `config.shared_secret` on laptop. |
