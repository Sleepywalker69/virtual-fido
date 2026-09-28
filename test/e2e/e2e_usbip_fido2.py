#!/usr/bin/env python3
"""End-to-end tests for virtual-fido, driven over USB/IP without a kernel driver.

The script plays the part of the host computer: it speaks the USB/IP protocol to
the virtual-fido server (OP_REQ_IMPORT, CMD_SUBMIT, CMD_UNLINK) exactly like the
Linux vhci-hcd or Windows usbip-win2 drivers do, keeps interrupt-IN URBs pending
like the HID class driver, and bridges the HID reports into python-fido2. The
python-fido2 WebAuthn client then acts as the browser/OS (PIN handling,
extensions) and python-fido2's Fido2Server verifies every response the way a
website would.

Approvals are controlled through a policy file that the server under test reads
on every approval request ("approve", "deny" or "delay <ms> approve|deny").

Usage:
    pip install fido2
    python3 e2e_usbip_fido2.py --policy-file /tmp/policy.txt [--pin 1234]
"""

import argparse
import hashlib
import os
import queue
import socket
import struct
import sys
import threading
import time
import traceback

from fido2.client import (
    ClientError,
    DefaultClientDataCollector,
    Fido2Client,
    UserInteraction,
)
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import ClientPin, Ctap2
from fido2.hid import CtapHidConnection, CtapHidDevice, HidDescriptor
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

USBIP_VERSION = 0x0111
OP_REQ_IMPORT, OP_REP_IMPORT = 0x8003, 0x0003
CMD_SUBMIT, CMD_UNLINK, RET_SUBMIT, RET_UNLINK = 1, 2, 3, 4
DIR_OUT, DIR_IN = 0, 1
EP_CTRL, EP_IN, EP_OUT = 0, 1, 2
EPIPE, ECONNRESET = 32, 104

RP = PublicKeyCredentialRpEntity(id="example.com", name="Example RP")
ORIGIN = "https://example.com"
READ_TIMEOUT = 30


class UsbipError(Exception):
    pass


class UsbipHost:
    """Minimal USB/IP client (the role vhci-hcd / usbip-win2 play)."""

    def __init__(self, host, port, busid="2-2", in_urbs=1, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.sendall(
            struct.pack(">HHI", USBIP_VERSION, OP_REQ_IMPORT, 0)
            + busid.encode().ljust(32, b"\0")
        )
        _ver, code, status = struct.unpack(">HHI", self._recvn(8))
        if code != OP_REP_IMPORT or status != 0:
            raise UsbipError(f"OP_REQ_IMPORT failed: code={code:#x} status={status}")
        self.device_info = self._recvn(312)
        self.sock.settimeout(None)
        self._lock = threading.Lock()
        self._seq = 0
        self._pending = {}
        self._unlinks = {}
        self.in_packets = queue.Queue()
        self.unlink_results = queue.Queue()
        self.ret_after_unlink = 0
        self.closed = False
        self.error = None
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        for _ in range(in_urbs):
            self.submit_in()

    def _recvn(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("USB/IP connection closed by server")
            buf += chunk
        return bytes(buf)

    def submit(self, direction, ep, length, data=b"", setup=b"\0" * 8, reply=True):
        q = queue.Queue() if reply else None
        with self._lock:
            self._seq += 1
            seq = self._seq
            self._pending[seq] = {"dir": direction, "ep": ep, "q": q, "unlinked": False}
            hdr = struct.pack(">IIIII", CMD_SUBMIT, seq, (2 << 16) | 2, direction, ep)
            body = struct.pack(">IIIII", 0, length, 0, 0, 0) + setup
            self.sock.sendall(hdr + body + (data if direction == DIR_OUT else b""))
        return seq, q

    def submit_in(self):
        return self.submit(DIR_IN, EP_IN, 64, reply=False)[0]

    def unlink(self, target_seq):
        with self._lock:
            if target_seq in self._pending:
                self._pending[target_seq]["unlinked"] = True
            self._seq += 1
            seq = self._seq
            self._unlinks[seq] = target_seq
            hdr = struct.pack(">IIIII", CMD_UNLINK, seq, (2 << 16) | 2, 0, 0)
            self.sock.sendall(hdr + struct.pack(">I", target_seq) + b"\0" * 24)
        return seq

    def _read_loop(self):
        try:
            while True:
                cmd, seq, _devid, _dir, _ep = struct.unpack(">IIIII", self._recvn(20))
                if cmd == RET_SUBMIT:
                    status, actual, _sf, _np, _ec = struct.unpack(">iIIII", self._recvn(20))
                    self._recvn(8)
                    with self._lock:
                        info = self._pending.pop(seq, None)
                    if info is None:
                        raise UsbipError(f"RET_SUBMIT for unknown seqnum {seq}")
                    data = self._recvn(actual) if info["dir"] == DIR_IN and actual else b""
                    if info["unlinked"]:
                        self.ret_after_unlink += 1
                        continue
                    if info["q"] is not None:
                        info["q"].put((status, data))
                    elif info["ep"] == EP_IN:
                        if status == 0 and data:
                            self.in_packets.put(data)
                        if not self.closed:
                            self.submit_in()
                elif cmd == RET_UNLINK:
                    (status,) = struct.unpack(">i", self._recvn(4))
                    self._recvn(24)
                    with self._lock:
                        target = self._unlinks.pop(seq, None)
                        if status == -ECONNRESET:
                            self._pending.pop(target, None)
                    self.unlink_results.put((target, status))
                else:
                    raise UsbipError(f"unexpected USB/IP command {cmd}")
        except Exception as e:  # noqa: BLE001 - surfaced to the reader
            if not self.closed:
                self.error = e
            self.in_packets.put(None)

    def control(self, bm_request_type, b_request, w_value, w_index, w_length, data=b"", timeout=3.0):
        setup = struct.pack("<BBHHH", bm_request_type, b_request, w_value, w_index, w_length)
        direction = DIR_IN if bm_request_type & 0x80 else DIR_OUT
        length = w_length if direction == DIR_IN else len(data)
        _seq, q = self.submit(direction, EP_CTRL, length, data=data, setup=setup)
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None

    def write_out(self, packet, timeout=5.0):
        _seq, q = self.submit(DIR_OUT, EP_OUT, len(packet), data=packet)
        try:
            status, _ = q.get(timeout=timeout)
        except queue.Empty:
            raise UsbipError("interrupt OUT transfer was never completed") from None
        if status != 0:
            raise UsbipError(f"interrupt OUT transfer failed with status {status}")

    def close(self):
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class UsbipCtapConnection(CtapHidConnection):
    """python-fido2 HID connection backed by UsbipHost.

    Like Chrome and libfido2, packets addressed to other CTAPHID channels are
    skipped (python-fido2 itself would raise on them); they are counted so stale
    traffic is still visible in the report.
    """

    def __init__(self, host):
        self.host = host
        self.device = None
        self.foreign_packets = 0

    def read_packet(self):
        while True:
            try:
                pkt = self.host.in_packets.get(timeout=READ_TIMEOUT)
            except queue.Empty:
                raise TimeoutError("no HID report from the authenticator") from None
            if pkt is None:
                raise ConnectionError(f"USB/IP connection lost: {self.host.error}")
            cid = struct.unpack_from(">I", pkt)[0]
            want = self.device._channel_id if self.device else 0xFFFFFFFF
            if cid != want:
                self.foreign_packets += 1
                continue
            return pkt

    def write_packet(self, data):
        self.host.write_out(bytes(data).ljust(64, b"\0"))

    def close(self):
        pass


def open_authenticator(args, in_urbs=None):
    host = UsbipHost(args.host, args.port, in_urbs=in_urbs or args.in_urbs)
    conn = UsbipCtapConnection(host)
    desc = HidDescriptor("usbip", 0, 0, 64, 64, "Virtual FIDO", None)
    dev = CtapHidDevice(desc, conn)
    conn.device = dev
    return host, conn, dev


class UI(UserInteraction):
    def __init__(self, pin=None):
        self.pin = pin
        self.pin_requests = 0
        self.up_prompts = 0

    def prompt_up(self):
        self.up_prompts += 1

    def request_pin(self, permissions, rp_id):
        self.pin_requests += 1
        if self.pin is None:
            raise ClientError(ClientError.ERR.BAD_REQUEST, "test did not expect a PIN prompt")
        return self.pin

    def request_uv(self, permissions, rp_id):
        return True


def webauthn_client(dev, pin=None):
    ui = UI(pin)
    return Fido2Client(dev, DefaultClientDataCollector(ORIGIN), user_interaction=ui), ui


def register(dev, server, name, rk, uv, pin=None, extensions=None):
    client, ui = webauthn_client(dev, pin)
    user = PublicKeyCredentialUserEntity(id=os.urandom(16), name=name, display_name=name.title())
    opts, state = server.register_begin(
        user, resident_key_requirement=rk, user_verification=uv, extensions=extensions
    )
    reg = client.make_credential(opts.public_key)
    auth_data = server.register_complete(state, reg)
    return auth_data, reg, ui


def login(dev, server, creds, uv, allow_list=True, pin=None, extensions=None):
    client, ui = webauthn_client(dev, pin)
    opts, state = server.authenticate_begin(
        credentials=creds if allow_list else None, user_verification=uv, extensions=extensions
    )
    sel = client.get_assertion(opts.public_key)
    responses = []
    for i in range(len(sel.get_assertions())):
        resp = sel.get_response(i)
        server.authenticate_complete(state, creds, resp)
        responses.append(resp)
    return responses, ui


def set_policy(args, policy):
    with open(args.policy_file, "w") as f:
        f.write(policy + "\n")


def ctap_err_name(e):
    try:
        return CtapError.ERR(e.code).name
    except ValueError:
        return hex(e.code)


class Runner:
    def __init__(self, args):
        self.args = args
        self.results = []

    def run(self, name, fn):
        print(f"--- {name}", flush=True)
        start = time.monotonic()
        try:
            detail = fn() or ""
            ok = True
        except AssertionError as e:
            ok, detail = False, f"assertion failed: {e}"
        except Exception as e:  # noqa: BLE001 - report every failure
            ok, detail = False, f"{type(e).__name__}: {e}"
            if isinstance(e, CtapError):
                detail = f"CtapError {ctap_err_name(e)}"
            if self.args.verbose:
                traceback.print_exc()
        took = time.monotonic() - start
        status = "PASS" if ok else "FAIL"
        print(f"    {status} ({took:.2f}s) {detail}", flush=True)
        self.results.append((name, ok, detail))
        return ok


def server_alive(args, attempts=10):
    for _ in range(attempts):
        try:
            host, _conn, dev = open_authenticator(args)
            try:
                Ctap2(dev).get_info()
                return True
            finally:
                host.close()
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    return False


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=3240)
    p.add_argument("--policy-file", required=True)
    p.add_argument("--pin", default="1234")
    p.add_argument("--in-urbs", type=int, default=1, help="interrupt-IN URBs kept pending (Linux=1, Windows>=2)")
    p.add_argument("--only", help="comma-separated scenario names to run")
    p.add_argument("--skip", default="", help="comma-separated scenario names to skip")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    set_policy(args, "approve")
    r = Runner(args)
    server = Fido2Server(RP)
    state = {"creds": [], "rk_creds": []}
    host, conn, dev = open_authenticator(args)
    ctap = Ctap2(dev)

    def s_enumeration():
        h = host
        checks = []
        dd = h.control(0x80, 6, 0x0100, 0, 18)
        assert dd and dd[0] == 0 and len(dd[1]) == 18 and dd[1][1] == 1, f"device descriptor: {dd}"
        cfg9 = h.control(0x80, 6, 0x0200, 0, 9)
        assert cfg9 and cfg9[0] == 0 and cfg9[1][1] == 2, f"config descriptor: {cfg9}"
        total = struct.unpack_from("<H", cfg9[1], 2)[0]
        cfg = h.control(0x80, 6, 0x0200, 0, 255)
        assert cfg and cfg[0] == 0 and len(cfg[1]) >= total, f"full config descriptor: {cfg}"
        checks.append(f"bConfigurationValue={cfg[1][5]}")
        if len(cfg[1]) != total:
            checks.append(f"config returned {len(cfg[1])} bytes for wTotalLength {total}")
        report_len = struct.unpack_from("<H", cfg[1], 9 + 9 + 7)[0]
        rep = h.control(0x81, 6, 0x2200, 0, report_len)
        assert rep and rep[0] == 0 and rep[1][:3] == bytes([0x06, 0xD0, 0xF1]), f"report descriptor: {rep}"
        s0 = h.control(0x80, 6, 0x0300, 0, 255)
        assert s0 and s0[0] == 0, f"string 0: {s0}"
        st = h.control(0x00, 9, cfg[1][5], 0, 0)
        assert st is not None and st[0] == 0, f"SET_CONFIGURATION: {st}"
        idle = h.control(0x21, 0x0A, 0, 0, 0)
        assert idle is not None and idle[0] == 0, f"SET_IDLE: {idle}"
        unsupported = {
            "MS OS string 0xEE": (0x80, 6, 0x03EE, 0, 18),
            "device qualifier": (0x80, 6, 0x0600, 0, 10),
        }
        problems = []
        for label, req in unsupported.items():
            res = h.control(*req)
            if res is None:
                problems.append(f"{label}: no reply (host would time out)")
            elif res[0] != -EPIPE:
                problems.append(f"{label}: status {res[0]} (expected STALL -32)")
        clear = h.control(0x02, 1, 0, 0x81, 0)
        if clear is None or clear[0] != 0:
            problems.append(f"CLEAR_FEATURE(ENDPOINT_HALT): {clear if clear else 'no reply'}")
        assert not problems, "; ".join(problems)
        return ", ".join(checks)

    def s_unlink():
        seq = host.submit_in()
        time.sleep(0.2)
        host.unlink(seq)
        target, status = host.unlink_results.get(timeout=5)
        assert target == seq, f"unlink reply for {target}, expected {seq}"
        assert status == -ECONNRESET, f"RET_UNLINK status {status}, expected -ECONNRESET"
        Ctap2(dev).get_info()  # traffic still flows afterwards
        return "pending IN URB unlinked cleanly"

    def s_ping_stress():
        # Multi-packet messages exercise CTAPHID reassembly and OUT-packet ordering.
        for i in range(40):
            payload = os.urandom(1024 + 97 * i)
            echo = dev.ping(payload)
            assert echo == payload, f"ping {i} ({len(payload)} bytes) echoed wrong data"
        return "40 multi-packet PINGs echoed intact"

    def s_get_info():
        info = ctap.get_info()
        return f"versions={info.versions} options={dict(info.options)} pin_protocols={info.pin_uv_protocols}"

    def s_register_login_allowlist():
        ad, _reg, _ui = register(dev, server, "alice", ResidentKeyRequirement.DISCOURAGED,
                                 UserVerificationRequirement.DISCOURAGED)
        state["creds"].append(ad.credential_data)
        responses, _ = login(dev, server, state["creds"], UserVerificationRequirement.DISCOURAGED)
        return f"registered + signed in; counter={responses[0].response.authenticator_data.counter}"

    def s_passkey_no_pin():
        info = ctap.get_info()
        if info.options.get("clientPin"):
            return "skipped: PIN already set"
        # Raw CTAP, as a browser sends it when the site does not ask for user
        # verification (python-fido2's own client insists on a PIN first).
        cdh = os.urandom(32)
        user = {"id": os.urandom(16), "name": "bob", "displayName": "Bob"}
        att = ctap.make_credential(cdh, {"id": RP.id, "name": RP.name}, user,
                                   [{"type": "public-key", "alg": -7}], options={"rk": True})
        cred = att.auth_data.credential_data
        state["rk_creds"].append(cred)
        cdh2 = os.urandom(32)
        resp = ctap.get_assertion(RP.id, cdh2)  # no allowList: usernameless
        assert resp.credential["id"] == cred.credential_id, "a different credential was returned"
        assert resp.auth_data.is_user_present(), "UP flag missing"
        cred.public_key.verify(resp.auth_data + cdh2, resp.signature)
        return "usernameless sign-in without PIN returned the passkey with a valid signature"

    def s_set_pin():
        info = ctap.get_info()
        if "clientPin" not in info.options:
            raise AssertionError("authenticator does not advertise clientPin support")
        if info.options["clientPin"]:
            return "PIN already set"
        ClientPin(ctap).set_pin(args.pin)
        assert Ctap2(dev).get_info().options.get("clientPin") is True
        return "PIN set through CTAP setPIN (like the Windows 'set up PIN' dialog)"

    def s_passkey_with_pin():
        ad, _reg, ui = register(dev, server, "carol", ResidentKeyRequirement.REQUIRED,
                                UserVerificationRequirement.REQUIRED, pin=args.pin)
        state["rk_creds"].append(ad.credential_data)
        assert ad.is_user_verified(), "UV flag missing after PIN"
        responses, ui2 = login(dev, server, state["rk_creds"], UserVerificationRequirement.REQUIRED,
                               allow_list=False, pin=args.pin)
        return f"PIN prompts={ui.pin_requests + ui2.pin_requests}, assertions={len(responses)}"

    def s_multi_account_uv():
        ad, _reg, _ui = register(dev, server, "dave", ResidentKeyRequirement.REQUIRED,
                                 UserVerificationRequirement.REQUIRED, pin=args.pin)
        state["rk_creds"].append(ad.credential_data)
        responses, _ = login(dev, server, state["rk_creds"], UserVerificationRequirement.REQUIRED,
                             allow_list=False, pin=args.pin)
        assert len(responses) >= 2, f"expected several accounts, got {len(responses)}"
        return f"all {len(responses)} accounts verified with UV (incl. GetNextAssertion)"

    def s_prf():
        ad, _reg, _ui = register(dev, server, "erin", ResidentKeyRequirement.DISCOURAGED,
                                 UserVerificationRequirement.REQUIRED, pin=args.pin,
                                 extensions={"prf": {}})
        creds = [ad.credential_data]
        salt = os.urandom(32)
        outs = []
        for _ in range(2):
            responses, _ = login(dev, server, creds, UserVerificationRequirement.REQUIRED, pin=args.pin,
                                 extensions={"prf": {"eval": {"first": salt}}})
            ext = responses[0].client_extension_results
            prf = ext.get("prf") if ext else None
            assert prf and prf.get("results", {}).get("first"), f"no PRF output: {ext}"
            outs.append(prf["results"]["first"])
        assert outs[0] == outs[1], "PRF output not stable for the same salt"
        state["prf_cred"] = ad.credential_data
        return "PRF/hmac-secret output returned and stable"

    def s_hmac_secret_reused_ecdh():
        cred = state.get("prf_cred")
        if cred is None:
            raise AssertionError("needs the prf scenario")
        cp = ClientPin(ctap)
        key_agreement, shared = cp._get_shared_secret()  # one ECDH, reused below (libfido2 style)
        pin_hash = hashlib.sha256(args.pin.encode()).digest()[:16]
        res = ctap.client_pin(
            cp.protocol.VERSION, ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
            key_agreement=key_agreement, pin_hash_enc=cp.protocol.encrypt(shared, pin_hash),
        )
        token = cp.protocol.decrypt(shared, res[ClientPin.RESULT.PIN_UV_TOKEN])
        salt = os.urandom(32)
        salt_enc = cp.protocol.encrypt(shared, salt)
        cdh = os.urandom(32)
        resp = ctap.get_assertion(
            RP.id, cdh, allow_list=[{"type": "public-key", "id": cred.credential_id}],
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc,
                                        3: cp.protocol.authenticate(shared, salt_enc)}},
            pin_uv_param=cp.protocol.authenticate(token, cdh), pin_uv_protocol=cp.protocol.VERSION,
        )
        exts = resp.auth_data.extensions or {}
        assert "hmac-secret" in exts, "no hmac-secret output when the PIN key agreement is reused"
        return "hmac-secret works with a reused key agreement"

    def s_keepalive_upneeded():
        set_policy(args, "delay 1500 approve")
        seen = []
        try:
            cred = state["creds"][0]
            cdh = os.urandom(32)
            Ctap2(dev).get_assertion(RP.id, cdh, allow_list=[{"type": "public-key", "id": cred.credential_id}],
                                     on_keepalive=seen.append)
        finally:
            set_policy(args, "approve")
        names = [STATUS(s).name for s in seen]
        assert STATUS.UPNEEDED in seen, f"keepalive statuses while waiting for approval: {names}"
        return f"keepalive statuses: {names}"

    def s_cancel():
        set_policy(args, "delay 6000 approve")
        ev = threading.Event()
        out = {}

        def worker():
            try:
                cred = state["creds"][0]
                Ctap2(dev).get_assertion(RP.id, os.urandom(32),
                                         allow_list=[{"type": "public-key", "id": cred.credential_id}], event=ev)
                out["result"] = "success"
            except CtapError as e:
                out["result"] = ctap_err_name(e)
            except Exception as e:  # noqa: BLE001
                out["result"] = f"{type(e).__name__}: {e}"
            out["t"] = time.monotonic()

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.7)
        t0 = time.monotonic()
        ev.set()
        t.join(15)
        set_policy(args, "approve")
        took = out.get("t", time.monotonic()) - t0
        assert out.get("result") == "KEEPALIVE_CANCEL", f"after CTAPHID_CANCEL got {out.get('result')} after {took:.1f}s"
        assert took < 2.0, f"cancel took {took:.1f}s"
        return f"cancelled in {took:.2f}s"

    def s_bad_key_agreement():
        bad = {1: 2, 3: -25, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}  # not on P-256
        try:
            ctap.client_pin(1, ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY, key_agreement=bad,
                            pin_hash_enc=b"\0" * 16)
            outcome = "accepted"
        except CtapError as e:
            outcome = ctap_err_name(e)
        except Exception as e:  # noqa: BLE001
            outcome = f"{type(e).__name__}"
        try:
            Ctap2(dev).get_info()
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"authenticator died after an off-curve key agreement (reply: {outcome}): {e}")
        assert outcome != "accepted", "off-curve key agreement accepted"
        return f"rejected with {outcome}; authenticator still alive"

    def s_detach_during_approval():
        nonlocal host, conn, dev, ctap
        host.close()  # only one host can import the device at a time
        time.sleep(0.2)
        set_policy(args, "delay 2000 approve")
        h2, _c2, d2 = open_authenticator(args)
        cred = state["creds"][0]

        def worker():
            try:
                Ctap2(d2).get_assertion(RP.id, os.urandom(32),
                                        allow_list=[{"type": "public-key", "id": cred.credential_id}])
            except Exception:  # noqa: BLE001 - connection is torn down on purpose
                pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        time.sleep(0.5)
        h2.close()
        time.sleep(3.0)
        set_policy(args, "approve")
        assert server_alive(args), "authenticator died after the host detached mid-request"
        host, conn, dev = open_authenticator(args)
        ctap = Ctap2(dev)
        return "authenticator survived a detach during approval"

    def s_wrong_pin_lockout():
        cp = ClientPin(Ctap2(dev))
        before = cp.get_pin_retries()[0]
        errs = []
        for _ in range(3):
            try:
                cp.get_pin_token("0000")
                errs.append("accepted")
            except CtapError as e:
                errs.append(ctap_err_name(e))
        after = ClientPin(Ctap2(dev)).get_pin_retries()[0]
        assert errs[-1] == "PIN_AUTH_BLOCKED", f"wrong-PIN replies: {errs}"
        assert after == before - 3, f"retries {before} -> {after}"
        return f"replies={errs}, retries {before}->{after}"

    scenarios = [
        ("enumeration", s_enumeration),
        ("unlink", s_unlink),
        ("ping_stress", s_ping_stress),
        ("get_info", s_get_info),
        ("register_login_allowlist", s_register_login_allowlist),
        ("passkey_no_pin", s_passkey_no_pin),
        ("set_pin", s_set_pin),
        ("passkey_with_pin", s_passkey_with_pin),
        ("multi_account_uv", s_multi_account_uv),
        ("prf", s_prf),
        ("hmac_secret_reused_ecdh", s_hmac_secret_reused_ecdh),
        ("keepalive_upneeded", s_keepalive_upneeded),
        ("cancel", s_cancel),
        ("bad_key_agreement", s_bad_key_agreement),
        ("detach_during_approval", s_detach_during_approval),
        ("wrong_pin_lockout", s_wrong_pin_lockout),
    ]
    only = set(filter(None, (args.only or "").split(",")))
    skip = set(filter(None, args.skip.split(",")))
    for name, fn in scenarios:
        if (only and name not in only) or name in skip:
            continue
        r.run(name, fn)
        if host.error is not None:
            # A scenario may have killed the connection (or the server): reconnect.
            try:
                host.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                host, conn, dev = open_authenticator(args)
                ctap = Ctap2(dev)
            except Exception as e:  # noqa: BLE001
                print(f"!!! cannot reconnect to the authenticator: {e}")
                break

    print()
    print(f"stale packets for other channels skipped: {conn.foreign_packets}; "
          f"RET_SUBMIT after successful unlink: {host.ret_after_unlink}")
    failed = [n for n, ok, _ in r.results if not ok]
    print(f"{len(r.results) - len(failed)}/{len(r.results)} scenarios passed")
    for n, ok, detail in r.results:
        print(f"  {'PASS' if ok else 'FAIL'}  {n}: {detail}")
    try:
        host.close()
    except Exception:  # noqa: BLE001
        pass
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
