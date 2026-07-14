"""Regression tests for the WMI host-info bind (nxc/protocols/wmi.py) and the
shared random-name helper (nxc/helpers/misc.py).

IoC carry-over (Phase 7): NetExec's own DumpNTLMInfo-style bind hardcoded the
tool tells we removed from the impacket fork -- a lone NDR32 context, the fixed
``auth_ctx_id = 79231``, and ``0xFF`` auth padding -- and ``gen_random_string``
emitted letters-only, no-repeat identifiers. These tests pin the Windows-like
shape so the tells cannot silently regress.
"""
from os.path import dirname, join
from importlib.util import module_from_spec, spec_from_file_location

import pytest
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT


@pytest.fixture(scope="module")
def wmi_module():
    # nxc/protocols/wmi.py is shadowed by the nxc/protocols/wmi/ package on a
    # normal import, so load the file directly -- exactly how NetExec's protocol
    # loader does, and how test_smb_signing.py loads smb.py.
    wmi_path = join(dirname(dirname(__file__)), "nxc", "protocols", "wmi.py")
    spec = spec_from_file_location("wmiproto", wmi_path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bind_uses_small_auth_ctx_id_not_79231(wmi_module):
    packet = wmi_module.build_ntlm_info_bind()
    assert packet["sec_trailer"]["auth_ctx_id"] == 1
    assert packet["sec_trailer"]["auth_ctx_id"] != 79231
    assert packet["sec_trailer"]["auth_type"] == RPC_C_AUTHN_WINNT


def test_bind_offers_btfn_second_context(wmi_module):
    # A real Windows client offers a 2nd (Bind-Time-Feature-Negotiation) context,
    # not a lone NDR32 one (IoC 37). Both transfer syntaxes must be on the wire.
    pdu = packet_pdu = wmi_module.build_ntlm_info_bind()["pduData"]
    assert wmi_module.NDR32_TRANSFER_SYNTAX in pdu
    assert wmi_module.BTFN_TRANSFER_SYNTAX in packet_pdu


def test_bind_pads_with_zero_not_ff(wmi_module):
    packet = wmi_module.build_ntlm_info_bind()
    try:
        pad_len = packet["sec_trailer"]["auth_pad_len"]
    except KeyError:
        pad_len = 0  # auth_pad_len is only set when the PDU needs padding
    if pad_len:
        # Windows zero-fills auth padding; the old code appended 0xFF (IoC 40/49).
        assert packet["pduData"][-pad_len:] == b"\x00" * pad_len
    # The old fixed 0xFF pad must never appear at the tail regardless.
    assert not packet["pduData"].endswith(b"\xff")


def test_bind_sends_valid_ntlm_negotiate(wmi_module):
    packet = wmi_module.build_ntlm_info_bind()
    auth_obj = packet["auth_data"]
    # getNTLMSSPType1 returns an NTLMAuthNegotiate structure; serialize to bytes.
    auth = auth_obj.getData() if hasattr(auth_obj, "getData") else bytes(auth_obj)
    assert auth[:8] == b"NTLMSSP\x00"          # a real NTLMSSP token
    assert int.from_bytes(auth[8:12], "little") == 1   # message type 1 (NEGOTIATE)


def test_gen_random_string_is_alphanumeric_and_can_repeat():
    from nxc.helpers.misc import gen_random_string
    import string

    alnum = set(string.ascii_letters + string.digits)
    # Length is honored and the charset is alphanumeric (was ascii_letters only).
    sample = gen_random_string(24)
    assert len(sample) == 24
    assert set(sample) <= alnum

    # Over a long draw, digits appear and characters repeat -- neither was possible
    # with random.sample(ascii_letters, n) (letters-only, guaranteed no-repeat).
    big = gen_random_string(1000)
    assert any(c.isdigit() for c in big)
    assert len(set(big)) < len(big)


def test_gen_share_name_is_realistic():
    from nxc.helpers import misc

    # Default: a realistic Windows-shaped share label built from a known base
    # (defeats the old fixed ^[A-Z]{5}$ token), never a bare 5-char random string.
    for _ in range(50):
        name = misc.gen_share_name()
        base = name.rstrip("$0123456789")
        assert base in misc._SHARE_LABELS
        assert "$" not in name[:-1]      # optional hidden-share '$' only ever trails


def test_gen_registry_path_is_com_class_shaped():
    import re
    from nxc.helpers.misc import gen_registry_path

    # Software\Classes\{GUID} -- a realistic COM-class key (indistinguishable from a
    # legitimate class registration), never the old Software\Classes\<random8> tell.
    for _ in range(20):
        p = gen_registry_path()
        assert re.fullmatch(
            r"Software\\Classes\\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}", p), p


def test_wmiexec_registry_path_is_hardened():
    # The WMI reg-out exec method must build __registry_Path from the realistic
    # helper, not the bare Software\Classes\<random8> token it used before.
    wx = join(dirname(dirname(__file__)), "nxc", "protocols", "wmi", "wmiexec.py")
    src = open(wx).read()
    assert "gen_registry_path()" in src
    assert "gen_random_string" not in src         # old tell fully removed


def test_smb_share_name_honors_env_override(monkeypatch):
    # smb.py is shadowed by the nxc/protocols/smb/ package on a normal import, so
    # load the module file directly (same approach as test_smb_signing.py). With
    # NXC_SMB_SHARE_NAME set, the module-level smb_share_name must use it verbatim.
    monkeypatch.setenv("NXC_SMB_SHARE_NAME", "CustomShare$")
    smb_path = join(dirname(dirname(__file__)), "nxc", "protocols", "smb.py")
    spec = spec_from_file_location("smbproto_envtest", smb_path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.smb_share_name == "CustomShare$"
