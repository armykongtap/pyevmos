from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping, Sequence, overload

import requests
from typing_extensions import Concatenate, ParamSpec

from evmos.eip712 import (
    EIPToSign,
    create_eip712,
    generate_fee,
    generate_message,
    generate_message_with_multiple_transactions,
    generate_types,
)
from evmos.proto import (
    MessageGenerated,
    create_transaction,
    create_transaction_with_multiple_messages,
)
from evmos.proto.transactions import TxGeneratedBase as TxGeneratedBase
from evmos.provider import generate_endpoint_account
from evmos.utils.doc import _inherit


@dataclass
class Fee:
    """Fee for message."""

    amount: str
    """Fee amount (stringified number, like '1000')."""
    denom: str
    """Denomination."""
    gas: str
    """Gas price."""


@dataclass
class Sender:
    """Message sender."""

    account_address: str
    """Account address (bech32, ``evmos1...``)."""
    sequence: int = 0
    """Account nonce - amount of previously sent transactions."""
    account_number: int = 0
    """Internal account number."""
    pubkey: str = ""
    """Account public key."""
    pubkey_type: str = "/ethermint.crypto.v1.ethsecp256k1.PubKey"
    """Public key type."""

    def update_from_chain(self, url: str = "http://127.0.0.1:1317") -> None:
        """Set `sequence`, `account_number` and possibly `pubkey` from API response."""
        response = requests.get(
            f"{url}{generate_endpoint_account(self.account_address)}"
        )
        resp = response.json()

        self.sequence = int(resp["account"]["base_account"]["sequence"])
        self.account_number = int(resp["account"]["base_account"]["account_number"])
        if not self.pubkey:
            self.pubkey = resp["account"]["base_account"]["pub_key"]["key"]
            self.pubkey_type = resp["account"]["base_account"]["pub_key"]["@type"]

    @property
    def algo(self) -> str:
        """Public key algorithm."""
        return self.pubkey_type.split(".")[-2]


@dataclass
class Chain:
    """Chain definition."""

    chain_id: int
    """Main chain ID."""
    cosmos_chain_id: str
    """Cosmos chain ID."""


@dataclass
class TxGenerated(TxGeneratedBase):
    """Transaction generated by this library (with EIP to sign)."""

    eip_to_sign: EIPToSign
    """EIP message to sign for EIP-712 transactions."""


_P = ParamSpec("_P")


def to_generated_base(
    func: Callable[Concatenate[str, _P], MessageGenerated[Any]]
) -> Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGeneratedBase]:
    """Wrap function returning message with transaction base."""

    # Not using functools.wraps, because signature is altered
    @_inherit(func)
    def inner(
        chain: Chain,
        sender: Sender,
        fee: Fee,
        memo: str,
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> TxGeneratedBase:
        msg_cosmos = func(sender.account_address, *args, **kwargs)

        tx = create_transaction(
            msg_cosmos,
            memo,
            fee.amount,
            fee.denom,
            int(fee.gas),
            sender.algo,
            sender.pubkey,
            sender.sequence,
            sender.account_number,
            chain.cosmos_chain_id,
        )

        return TxGeneratedBase(
            sign_direct=tx.sign_direct,
            legacy_amino=tx.legacy_amino,
        )

    return inner


@overload
def to_generated(
    types_def: dict[str, Any], *, proto: Literal[True], many: Literal[True]
) -> Callable[
    [
        Callable[
            Concatenate[str, _P],
            tuple[Sequence[Mapping[str, Any]], Sequence[MessageGenerated[Any]]],
        ]
    ],
    Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
]: ...


@overload
def to_generated(
    types_def: dict[str, Any], *, proto: Literal[False] = ..., many: Literal[True]
) -> Callable[
    [Callable[_P, tuple[Sequence[Mapping[str, Any]], Sequence[MessageGenerated[Any]]]]],
    Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
]: ...


@overload
def to_generated(
    types_def: dict[str, Any], *, proto: Literal[True], many: Literal[False] = ...
) -> Callable[
    [Callable[Concatenate[str, _P], tuple[Mapping[str, Any], MessageGenerated[Any]]]],
    Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
]: ...


@overload
def to_generated(
    types_def: dict[str, Any],
    *,
    proto: Literal[False] = ...,
    many: Literal[False] = ...,
) -> Callable[
    [Callable[_P, tuple[Mapping[str, Any], MessageGenerated[Any]]]],
    Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
]: ...


def to_generated(
    types_def: dict[str, Any], *, proto: bool = False, many: bool = False
) -> (
    Callable[
        [Callable[_P, tuple[Mapping[str, Any], MessageGenerated[Any]]]],
        Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
    ]
    | Callable[
        [
            Callable[
                Concatenate[str, _P], tuple[Mapping[str, Any], MessageGenerated[Any]]
            ]
        ],
        Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
    ]
    | Callable[
        [
            Callable[
                _P, tuple[Sequence[Mapping[str, Any]], Sequence[MessageGenerated[Any]]]
            ]
        ],
        Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
    ]
    | Callable[
        [
            Callable[
                Concatenate[str, _P],
                tuple[Sequence[Mapping[str, Any]], Sequence[MessageGenerated[Any]]],
            ]
        ],
        Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated],
    ]
):
    """Wrap function returning message with transaction."""

    def _inner(
        chain: Chain,
        sender: Sender,
        fee: Fee,
        memo: str,
        msg: Mapping[str, Any] | Sequence[Mapping[str, Any]],
        msg_cosmos: MessageGenerated[Any] | Sequence[MessageGenerated[Any]],
    ) -> TxGenerated:
        # EIP712
        fee_object = generate_fee(
            fee.amount,
            fee.denom,
            fee.gas,
            sender.account_address,
        )
        types = generate_types(types_def)

        # No, I won't make it even more ugly with further typing
        messages = (  # type: ignore
            generate_message_with_multiple_transactions if many else generate_message
        )(
            str(sender.account_number),
            str(sender.sequence),
            chain.cosmos_chain_id,
            memo,
            fee_object,
            msg,
        )
        eip_to_sign = create_eip712(types, chain.chain_id, messages)

        # Cosmos

        tx = (
            create_transaction_with_multiple_messages if many else create_transaction
        )(
            msg_cosmos,
            memo,
            fee.amount,
            fee.denom,
            int(fee.gas),
            sender.algo,
            sender.pubkey,
            sender.sequence,
            sender.account_number,
            chain.cosmos_chain_id,
        )

        return TxGenerated(
            sign_direct=tx.sign_direct,
            legacy_amino=tx.legacy_amino,
            eip_to_sign=eip_to_sign,
        )

    if proto:

        def decorator(
            func: Callable[
                Concatenate[str, _P],
                tuple[
                    Mapping[str, Any] | Sequence[Mapping[str, Any]],
                    MessageGenerated[Any] | Sequence[MessageGenerated[Any]],
                ],
            ]
        ) -> Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated]:
            @_inherit(func)
            def inner(
                chain: Chain,
                sender: Sender,
                fee: Fee,
                memo: str,
                *args: _P.args,
                **kwargs: _P.kwargs,
            ) -> TxGenerated:
                msg, msg_cosmos = func(sender.account_address, *args, **kwargs)
                return _inner(chain, sender, fee, memo, msg, msg_cosmos)

            return inner

        return decorator

    else:

        def decorator2(
            func: Callable[
                _P,
                tuple[
                    Mapping[str, Any] | Sequence[Mapping[str, Any]],
                    MessageGenerated[Any] | Sequence[MessageGenerated[Any]],
                ],
            ]
        ) -> Callable[Concatenate[Chain, Sender, Fee, str, _P], TxGenerated]:
            @_inherit(func)
            def inner(
                chain: Chain,
                sender: Sender,
                fee: Fee,
                memo: str,
                *args: _P.args,
                **kwargs: _P.kwargs,
            ) -> TxGenerated:
                msg, msg_cosmos = func(*args, **kwargs)
                return _inner(chain, sender, fee, memo, msg, msg_cosmos)

            return inner

        return decorator2
