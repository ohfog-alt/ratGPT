from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .encoding import base64_standard, base64url, json_compact
from .state import DEFAULT_CONTROLLER_DEVICE_KEY_PATH, DEFAULT_CONTROLLER_ENROLLMENT_PATH
from .state import read_json_if_exists, write_json_file

ALGORITHM = "ecdsa_p256_sha256"
DEFAULT_PROTECTION_CLASS = "os_protected_nonextractable"
SIGNING_DOMAIN = "codex-device-key-sign-payload/v1"


@dataclass
class DeviceKey:
    key_id: str
    algorithm: str
    protection_class: str
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    public_key_spki_der_base64: str
    public_key_sha256_base64url: str


@dataclass
class KeyState:
    created: bool
    key_path: Path
    device_key: DeviceKey


def _key_material(
    private_key: ec.EllipticCurvePrivateKey,
    key_id: str,
    protection_class: str = DEFAULT_PROTECTION_CLASS,
) -> DeviceKey:
    public_key = private_key.public_key()
    public_key_spki_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return DeviceKey(
        key_id=key_id,
        algorithm=ALGORITHM,
        protection_class=protection_class,
        private_key=private_key,
        public_key=public_key,
        public_key_spki_der_base64=base64_standard(public_key_spki_der),
        public_key_sha256_base64url=base64url(hashlib.sha256(public_key_spki_der).digest()),
    )


def load_or_create_software_device_key(
    key_path: str | Path = DEFAULT_CONTROLLER_DEVICE_KEY_PATH,
    protection_class: str = DEFAULT_PROTECTION_CLASS,
) -> KeyState:
    path = Path(key_path).expanduser()
    existing = read_json_if_exists(path)
    if existing:
        private_key = serialization.load_pem_private_key(
            existing["privateKeyPkcs8Pem"].encode("utf-8"),
            password=None,
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise RuntimeError(f"Stored device key at {path} is not an EC private key.")
        return KeyState(
            created=False,
            key_path=path,
            device_key=_key_material(
                private_key,
                existing["keyId"],
                existing.get("protectionClass", protection_class),
            ),
        )

    private_key = ec.generate_private_key(ec.SECP256R1())
    key_id = str(uuid.uuid4())
    private_key_pkcs8_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    device_key = _key_material(private_key, key_id, protection_class)
    write_json_file(
        path,
        {
            "version": 1,
            "keyId": key_id,
            "algorithm": ALGORITHM,
            "protectionClass": protection_class,
            "privateKeyPkcs8Pem": private_key_pkcs8_pem,
        },
    )
    return KeyState(created=True, key_path=path, device_key=device_key)


def device_identity(device_key: DeviceKey) -> dict[str, str]:
    return {
        "key_id": device_key.key_id,
        "public_key_spki_der_base64": device_key.public_key_spki_der_base64,
        "algorithm": device_key.algorithm,
        "protection_class": device_key.protection_class,
    }


def device_identity_hash(device_key: DeviceKey) -> str:
    identity_for_hash = {
        "algorithm": device_key.algorithm,
        "keyId": device_key.key_id,
        "protectionClass": device_key.protection_class,
        "publicKeySpkiDerBase64": device_key.public_key_spki_der_base64,
    }
    return base64url(hashlib.sha256(json_compact(identity_for_hash).encode("utf-8")).digest())


def _canonical_device_key_payload(payload: dict[str, Any]) -> dict[str, Any]:
    payload_type = payload.get("type")
    if payload_type == "remoteControlClientConnection":
        return {
            "accountUserId": payload.get("accountUserId"),
            "audience": payload.get("audience"),
            "clientId": payload.get("clientId"),
            "nonce": payload.get("nonce"),
            "scopes": payload.get("scopes"),
            "sessionId": payload.get("sessionId"),
            "targetOrigin": payload.get("targetOrigin"),
            "targetPath": payload.get("targetPath"),
            "tokenExpiresAt": payload.get("tokenExpiresAt"),
            "tokenSha256Base64url": payload.get("tokenSha256Base64url"),
            "type": payload_type,
        }
    if payload_type == "remoteControlClientEnrollment":
        return {
            "accountUserId": payload.get("accountUserId"),
            "audience": payload.get("audience"),
            "challengeExpiresAt": payload.get("challengeExpiresAt"),
            "challengeId": payload.get("challengeId"),
            "clientId": payload.get("clientId"),
            "deviceIdentitySha256Base64url": payload.get("deviceIdentitySha256Base64url"),
            "nonce": payload.get("nonce"),
            "targetOrigin": payload.get("targetOrigin"),
            "targetPath": payload.get("targetPath"),
            "type": payload_type,
        }
    raise RuntimeError(f"Unknown device-key payload type: {payload_type!r}")


def sign_device_key_payload(device_key: DeviceKey, payload: dict[str, Any]) -> dict[str, Any]:
    signed_payload = json_compact(
        {
            "domain": SIGNING_DOMAIN,
            "payload": _canonical_device_key_payload(payload),
        }
    )
    signed_payload_bytes = signed_payload.encode("utf-8")
    signature = device_key.private_key.sign(signed_payload_bytes, ec.ECDSA(hashes.SHA256()))
    verified = True
    try:
        device_key.public_key.verify(signature, signed_payload_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        verified = False
    return {
        "keyId": device_key.key_id,
        "algorithm": device_key.algorithm,
        "signedPayload": signed_payload,
        "signedPayloadBase64": base64_standard(signed_payload_bytes),
        "signatureDerBase64": base64_standard(signature),
        "signatureDerLength": len(signature),
        "verified": verified,
    }


def build_enrollment_record(
    *,
    account_user_id: str,
    client_id: str,
    device_key: DeviceKey,
    source: str,
) -> dict[str, Any]:
    return {
        "version": 1,
        "accountUserId": account_user_id,
        "clientId": client_id,
        "keyId": device_key.key_id,
        "algorithm": device_key.algorithm,
        "protectionClass": device_key.protection_class,
        "publicKeySpkiDerBase64": device_key.public_key_spki_der_base64,
        "source": source,
    }


def write_enrollment(record: dict[str, Any], enrollment_path: str | Path = DEFAULT_CONTROLLER_ENROLLMENT_PATH) -> None:
    from .logutil import now_iso

    write_json_file(enrollment_path, {**record, "updatedAt": now_iso()})


def load_existing_controller_identity(
    *,
    device_key_path: str | Path = DEFAULT_CONTROLLER_DEVICE_KEY_PATH,
    enrollment_path: str | Path = DEFAULT_CONTROLLER_ENROLLMENT_PATH,
) -> tuple[KeyState, dict[str, Any]]:
    if not Path(device_key_path).expanduser().exists():
        raise RuntimeError(f"No chatex-python controller device key found at {device_key_path}.")
    if not Path(enrollment_path).expanduser().exists():
        raise RuntimeError(f"No chatex-python controller enrollment found at {enrollment_path}.")
    key_state = load_or_create_software_device_key(device_key_path)
    if key_state.created:
        raise RuntimeError(f"Refusing to use newly-created controller device key at {device_key_path}.")
    enrollment = read_json_if_exists(enrollment_path)
    if enrollment.get("keyId") != key_state.device_key.key_id:
        raise RuntimeError("Controller enrollment keyId does not match local device key.")
    return key_state, enrollment
