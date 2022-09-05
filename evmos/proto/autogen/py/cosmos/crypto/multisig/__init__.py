from __future__ import annotations

# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: cosmos/crypto/multisig/keys.proto
# plugin: python-betterproto
from dataclasses import dataclass

import betterproto
import betterproto.lib.google.protobuf as betterproto_lib_google_protobuf


@dataclass(eq=False, repr=False)
class LegacyAminoPubKey(betterproto.Message):
    """
    LegacyAminoPubKey specifies a public key type which nests multiple public
    keys and a threshold, it uses legacy amino address rules.
    """

    threshold: int = betterproto.uint32_field(1)
    public_keys: list[betterproto_lib_google_protobuf.Any] = betterproto.message_field(
        2
    )
