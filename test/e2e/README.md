# End-to-end tests over USB/IP

`e2e_usbip_fido2.py` plays the host computer without any kernel driver: it
speaks USB/IP to the authenticator exactly like Linux `vhci-hcd` or Windows
`usbip-win2` do (import, `CMD_SUBMIT`, `CMD_UNLINK`, pending interrupt-IN
transfers), bridges the HID reports into [python-fido2](https://github.com/Yubico/python-fido2),
and lets python-fido2's WebAuthn client (the "browser") and `Fido2Server`
(the "website") register, sign in, set a PIN, use PRF/hmac-secret, cancel
requests and detach mid-request.

`server/` runs the same authenticator core as the Windows app, headless, with
approvals taken from a policy file (`approve`, `deny`, `delay <ms> approve`).
It approves without asking anyone: use it for tests only.

```sh
pip install fido2
go build -o e2e-server ./test/e2e/server
./e2e-server -vault /tmp/e2e-vault.json -policy-file /tmp/policy.txt &
python3 test/e2e/e2e_usbip_fido2.py --policy-file /tmp/policy.txt
```

`--in-urbs 3` keeps several interrupt-IN transfers pending, like the Windows
HID driver; `-no-pin` on the server disables PIN support.
