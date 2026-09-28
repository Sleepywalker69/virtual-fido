# Virtual FIDO

> Also check out [Bulwark Passkey](https://bulwark.id), a passkey manager based on VirtualFIDO that is currently in beta!

Virtual FIDO is a virtual USB device that implements the FIDO2/U2F protocol (like a YubiKey) to support 2FA and WebAuthN. Please note that this software is still in beta and under active development, so APIs may be subject to change.

## Features

-   Windows app with approval pop-ups and a macropad hotkey; Linux support through USB/IP (Mac support coming later)
-   Connect using both U2F and FIDO2 protocols for both normal 2FA and WebAuthN, including passkeys (usernameless sign-in), PIN and the PRF/hmac-secret extension
-   Store credentials in an encrypted format with a passphrase
-   Store credential data anywhere (example provided: a local file)
-   Generic approval mechanism for credential creation and login (examples provided: a Windows pop-up/hotkey, and the terminal)

## How it works

Virtual FIDO creates a USB/IP server over local TCP (127.0.0.1:3240) to attach a virtual USB device. This USB device then emulates the USB/CTAP protocols to provide U2F/FIDO services to the host computer. Credentials created by the virtual device are stored in an encrypted local file, and nothing is signed until you approve it.

## Windows app

### One-time setup

1. Install **usbip-win2**, the USB/IP driver for Windows: download the installer from
   [github.com/vadimgrn/usbip-win2/releases](https://github.com/vadimgrn/usbip-win2/releases/latest) and run it.
   Its drivers are signed by Microsoft, so no test-signing mode is needed (Windows 10 1903+ x64, or Windows 11 ARM64).
2. Get `vfido.exe`: download the `vfido-windows` artifact from the latest successful
   [Windows build](../../actions/workflows/windows.yml) run, or build it yourself with Go 1.22+:

   ```
   go build -trimpath -ldflags "-H windowsgui" -o vfido.exe ./cmd/vfido-gui
   ```

### Using it

1. Run `vfido.exe`. The first time, choose a passphrase: it encrypts your passkeys
   (stored in `%APPDATA%\VirtualFIDO\vault.json`). You can let the app unlock automatically on this PC.
2. The app plugs the virtual security key into Windows. The status line turns to
   **Ready — Windows can use your security key** (click **Attach** if it doesn't).
3. On a website, register a security key or passkey. When Windows asks which device to use,
   pick **Security key**. The first time a site wants a PIN, Windows asks you to create one.
4. Virtual FIDO shows a pop-up naming the site. Click **Approve**, or press your approve hotkey.
   Esc, closing the pop-up, or waiting out the timeout denies the request.

The app keeps running in the notification area when you close the window (key icon: blue = ready,
amber = waiting for your approval, gray = stopped). Use **Exit** from the icon's menu to stop it; that
also unplugs the virtual key.

### Macropad approval

The **Approval** tab sets a global approve hotkey (default **F13**) and an optional deny hotkey.
Program a macropad key to send it: F13–F24 exist on no ordinary keyboard, so they never clash with typing.
Any combination such as `Ctrl+Alt+F12` works too.

### Troubleshooting

- *"Windows needs the free usbip-win2 driver"*: install it (step 1), then click **Attach**.
- *"could not listen on 127.0.0.1:3240"*: another copy of Virtual FIDO, or another USB/IP server, is running.
- The **Log** tab shows what happened; `vfido.exe --verbose` logs every USB/CTAP message.
- Forgot the PIN, or it is blocked after too many wrong tries: **PIN** tab → **Remove PIN**.

Note that Virtual FIDO is a software authenticator: its keys are protected by your passphrase and your
Windows account, not by tamper-resistant hardware, and its attestation certificate is self-signed.

## Command-line demo

Go to the [YubiKey test page](https://demo.yubico.com/webauthn-technical/registration) in order to test WebAuthN.

### Windows

Install usbip-win2 (see above), then run `go run ./cmd/demo start` to attach the USB device. Run `go run ./cmd/demo --help` to see more commands, such as to list or delete credentials from the file.

### Linux

Note that this tool requires elevated permissions.

1. Run `sudo modprobe vhci-hcd` to load the necessary drivers.
2. Run `sudo go run ./cmd/demo start` to start up the USB device server. Authenticate when `sudo` prompts you; this is necessary to attach the device.

Approvals default to a terminal prompt. `VFIDO_APPROVE_CMD`, `VFIDO_APPROVE_FIFO` and
`VFIDO_APPROVE_NOTIFY_CMD` redirect them to a script or device (see `cmd/demo/approval.go`).

## Tests

`go test ./...` runs the unit tests. `test/e2e` drives the authenticator over USB/IP from Python
with [python-fido2](https://github.com/Yubico/python-fido2) acting as browser and website, without
needing a kernel driver; see [test/e2e/README.md](test/e2e/README.md).
