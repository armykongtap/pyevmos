from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Final, Sequence

from eth_typing import HexStr
from eth_utils import keccak

from evmos.proto.autogen.py.cosmos.base.v1beta1 import Coin
from evmos.proto.autogen.py.cosmos.crypto import secp256k1 as secp
from evmos.proto.autogen.py.cosmos.tx import v1beta1 as tx
from evmos.proto.autogen.py.cosmos.tx.signing.v1beta1 import SignMode
from evmos.proto.autogen.py.ethermint.crypto.v1 import ethsecp256k1 as eth
from evmos.proto.utils import MessageGenerated, create_any_message

SIGN_DIRECT: Final = SignMode.SIGN_MODE_DIRECT
LEGACY_AMINO: Final = SignMode.SIGN_MODE_LEGACY_AMINO_JSON


@dataclass
class TxGeneratedSignInfo:
    """Type of :class:`TxGenerated` fields."""

    body: tx.TxBody
    """Transaction body."""
    auth_info: tx.AuthInfo
    """Transaction authentication info."""
    sign_bytes: HexStr
    """Raw bytes for signing as hex string."""


@dataclass
class TxGeneratedBase:
    """Transaction generated by this library."""

    sign_direct: TxGeneratedSignInfo
    """Data to sign directly (intended for keplr-style signing)."""
    legacy_amino: TxGeneratedSignInfo
    """Data to sign (intended for use with EIP712 signing)."""


def create_body_with_multiple_messages(messages: Sequence[Any], memo: str) -> tx.TxBody:
    """Create a TxBody instance.

    Create :class:`~evmos.proto.autogen.py.cosmos.tx.v1beta1.TxBody`
    with multiple messages provided.
    """
    return tx.TxBody(messages=list(map(create_any_message, messages)), memo=memo)


def create_body(message: Any, memo: str) -> tx.TxBody:
    """Create a TxBody instance.

    Create :class:`~evmos.proto.autogen.py.cosmos.tx.v1beta1.TxBody`
    with single message provided.
    """
    return create_body_with_multiple_messages([message], memo)


def create_fee(fee: str, denom: str, gas_limit: int) -> tx.Fee:
    """Create a Fee instance.

    Create :class:`~evmos.proto.autogen.py.cosmos.tx.v1beta1.Fee`
    with provided parameters.
    """
    return tx.Fee(
        amount=[Coin(denom=denom, amount=fee)],
        gas_limit=gas_limit,
    )


def create_signer_info(
    algo: str,
    public_key: bytes,
    sequence: int,
    mode: int | SignMode,
) -> tx.SignerInfo:
    """Create a SignerInfo instance.

    Create :class:`~evmos.proto.autogen.py.cosmos.tx.v1beta1.SignerInfo`
    with provided parameters.
    """
    # NOTE: secp256k1 is going to be removed from evmos
    if algo == "secp256k1":
        pubkey = MessageGenerated(
            message=secp.PubKey(key=public_key),
            path="cosmos.crypto.secp256k1.PubKey",
        )
    else:
        # NOTE: assume ethsecp256k1 by default because after mainnet is the only one
        # that is going to be supported
        pubkey = MessageGenerated(
            message=eth.PubKey(key=public_key),
            path="ethermint.crypto.v1.ethsecp256k1.PubKey",
        )

    return tx.SignerInfo(
        public_key=create_any_message(pubkey),
        mode_info=tx.ModeInfo(
            single=tx.ModeInfoSingle(mode=mode)  # type: ignore[arg-type]
        ),
        sequence=sequence,
    )


def create_auth_info(signer_info: tx.SignerInfo, fee: tx.Fee) -> tx.AuthInfo:
    """Create an AuthInfo instance.

    Create :class:`~evmos.proto.autogen.py.cosmos.tx.v1beta1.AuthInfo`
    with provided parameters.
    """
    return tx.AuthInfo(signer_infos=[signer_info], fee=fee)


def create_sig_doc(
    body_bytes: bytes, auth_info_bytes: bytes, chain_id: str, account_number: int
) -> tx.SignDoc:
    """Create a SignDoc instance.

    Create :class:`~evmos.proto.autogen.py.cosmos.tx.v1beta1.SignDoc`
    with provided parameters.
    """
    return tx.SignDoc(
        body_bytes=body_bytes,
        auth_info_bytes=auth_info_bytes,
        chain_id=chain_id,
        account_number=account_number,
    )


def create_transaction_with_multiple_messages(
    messages: Any,
    memo: str,
    fee: str,
    denom: str,
    gas_limit: int,
    algo: str,
    pub_key: str,
    sequence: int,
    account_number: int,
    chain_id: str,
) -> TxGeneratedBase:
    """Create transaction parameters with multiple messages."""
    body = create_body_with_multiple_messages(messages, memo)
    fee_message = create_fee(fee, denom, gas_limit)
    pub_key_decoded = base64.b64decode(pub_key)

    # AMINO
    sign_info_amino = create_signer_info(
        algo,
        bytes(pub_key_decoded),
        sequence,
        LEGACY_AMINO,
    )

    auth_info_amino = create_auth_info(sign_info_amino, fee_message)

    sign_doc_amino = create_sig_doc(
        bytes(body),
        bytes(auth_info_amino),
        chain_id,
        account_number,
    )

    to_sign_amino = keccak(bytes(sign_doc_amino))

    # SignDirect
    sign_info_direct = create_signer_info(
        algo,
        bytes(pub_key_decoded),
        sequence,
        SIGN_DIRECT,
    )

    auth_info_direct = create_auth_info(sign_info_direct, fee_message)

    sign_doc_direct = create_sig_doc(
        bytes(body),
        bytes(auth_info_direct),
        chain_id,
        account_number,
    )

    to_sign_direct = keccak(bytes(sign_doc_direct))

    return TxGeneratedBase(
        legacy_amino=TxGeneratedSignInfo(
            body=body,
            auth_info=auth_info_amino,
            sign_bytes=base64.b64encode(to_sign_amino).decode(),
        ),
        sign_direct=TxGeneratedSignInfo(
            body=body,
            auth_info=auth_info_direct,
            sign_bytes=base64.b64encode(to_sign_direct).decode(),
        ),
    )


def create_transaction(
    message: Any,
    memo: str,
    fee: str,
    denom: str,
    gas_limit: int,
    algo: str,
    pub_key: str,
    sequence: int,
    account_number: int,
    chain_id: str,
) -> TxGeneratedBase:
    """Create transaction parameters with a single message."""
    return create_transaction_with_multiple_messages(
        [message],
        memo,
        fee,
        denom,
        gas_limit,
        algo,
        pub_key,
        sequence,
        account_number,
        chain_id,
    )
