from __future__ import annotations

# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: ibc/applications/transfer/v1/genesis.proto, ibc/applications/transfer/v1/query.proto, ibc/applications/transfer/v1/transfer.proto, ibc/applications/transfer/v1/tx.proto
# plugin: python-betterproto
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

import betterproto
import grpclib
from betterproto.grpc.grpclib_server import ServiceBase

from .....cosmos.base import v1beta1 as ____cosmos_base_v1_beta1__
from .....cosmos.base.query import v1beta1 as ____cosmos_base_query_v1_beta1__
from ....core.client import v1 as ___core_client_v1__

if TYPE_CHECKING:
    import grpclib.server
    from betterproto.grpc.grpclib_client import MetadataLike
    from grpclib.metadata import Deadline


@dataclass(eq=False, repr=False)
class DenomTrace(betterproto.Message):
    """
    DenomTrace contains the base denomination for ICS20 fungible tokens and the
    source tracing information path.
    """

    path: str = betterproto.string_field(1)
    """
    path defines the chain of port/channel identifiers used for tracing the
    source of the fungible token.
    """

    base_denom: str = betterproto.string_field(2)
    """base denomination of the relayed fungible token."""


@dataclass(eq=False, repr=False)
class Params(betterproto.Message):
    """
    Params defines the set of IBC transfer parameters. NOTE: To prevent a
    single token from being transferred, set the TransfersEnabled parameter to
    true and then set the bank module's SendEnabled parameter for the
    denomination to false.
    """

    send_enabled: bool = betterproto.bool_field(1)
    """
    send_enabled enables or disables all cross-chain token transfers from this
    chain.
    """

    receive_enabled: bool = betterproto.bool_field(2)
    """
    receive_enabled enables or disables all cross-chain token transfers to this
    chain.
    """


@dataclass(eq=False, repr=False)
class QueryDenomTraceRequest(betterproto.Message):
    """
    QueryDenomTraceRequest is the request type for the Query/DenomTrace RPC
    method
    """

    hash: str = betterproto.string_field(1)
    """hash (in hex format) of the denomination trace information."""


@dataclass(eq=False, repr=False)
class QueryDenomTraceResponse(betterproto.Message):
    """
    QueryDenomTraceResponse is the response type for the Query/DenomTrace RPC
    method.
    """

    denom_trace: DenomTrace = betterproto.message_field(1)
    """denom_trace returns the requested denomination trace information."""


@dataclass(eq=False, repr=False)
class QueryDenomTracesRequest(betterproto.Message):
    """
    QueryConnectionsRequest is the request type for the Query/DenomTraces RPC
    method
    """

    pagination: ____cosmos_base_query_v1_beta1__.PageRequest = (
        betterproto.message_field(1)
    )
    """pagination defines an optional pagination for the request."""


@dataclass(eq=False, repr=False)
class QueryDenomTracesResponse(betterproto.Message):
    """
    QueryConnectionsResponse is the response type for the Query/DenomTraces RPC
    method.
    """

    denom_traces: list[DenomTrace] = betterproto.message_field(1)
    """denom_traces returns all denominations trace information."""

    pagination: ____cosmos_base_query_v1_beta1__.PageResponse = (
        betterproto.message_field(2)
    )
    """pagination defines the pagination in the response."""


@dataclass(eq=False, repr=False)
class QueryParamsRequest(betterproto.Message):
    """
    QueryParamsRequest is the request type for the Query/Params RPC method.
    """

    pass


@dataclass(eq=False, repr=False)
class QueryParamsResponse(betterproto.Message):
    """
    QueryParamsResponse is the response type for the Query/Params RPC method.
    """

    params: Params = betterproto.message_field(1)
    """params defines the parameters of the module."""


@dataclass(eq=False, repr=False)
class QueryDenomHashRequest(betterproto.Message):
    """
    QueryDenomHashRequest is the request type for the Query/DenomHash RPC
    method
    """

    trace: str = betterproto.string_field(1)
    """The denomination trace ([port_id]/[channel_id])+/[denom]"""


@dataclass(eq=False, repr=False)
class QueryDenomHashResponse(betterproto.Message):
    """
    QueryDenomHashResponse is the response type for the Query/DenomHash RPC
    method.
    """

    hash: str = betterproto.string_field(1)
    """hash (in hex format) of the denomination trace information."""


@dataclass(eq=False, repr=False)
class GenesisState(betterproto.Message):
    """GenesisState defines the ibc-transfer genesis state"""

    port_id: str = betterproto.string_field(1)
    denom_traces: list[DenomTrace] = betterproto.message_field(2)
    params: Params = betterproto.message_field(3)


@dataclass(eq=False, repr=False)
class MsgTransfer(betterproto.Message):
    """
    MsgTransfer defines a msg to transfer fungible tokens (i.e Coins) between
    ICS20 enabled chains. See ICS Spec here:
    https://github.com/cosmos/ibc/tree/master/spec/app/ics-020-fungible-token-
    transfer#data-structures
    """

    source_port: str = betterproto.string_field(1)
    """the port on which the packet will be sent"""

    source_channel: str = betterproto.string_field(2)
    """the channel by which the packet will be sent"""

    token: ____cosmos_base_v1_beta1__.Coin = betterproto.message_field(3)
    """the tokens to be transferred"""

    sender: str = betterproto.string_field(4)
    """the sender address"""

    receiver: str = betterproto.string_field(5)
    """the recipient address on the destination chain"""

    timeout_height: ___core_client_v1__.Height = betterproto.message_field(6)
    """
    Timeout height relative to the current block height. The timeout is
    disabled when set to 0.
    """

    timeout_timestamp: int = betterproto.uint64_field(7)
    """
    Timeout timestamp in absolute nanoseconds since unix epoch. The timeout is
    disabled when set to 0.
    """


@dataclass(eq=False, repr=False)
class MsgTransferResponse(betterproto.Message):
    """MsgTransferResponse defines the Msg/Transfer response type."""

    pass


class QueryStub(betterproto.ServiceStub):
    async def denom_trace(
        self,
        query_denom_trace_request: 'QueryDenomTraceRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'QueryDenomTraceResponse':
        return await self._unary_unary(
            '/ibc.applications.transfer.v1.Query/DenomTrace',
            query_denom_trace_request,
            QueryDenomTraceResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def denom_traces(
        self,
        query_denom_traces_request: 'QueryDenomTracesRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'QueryDenomTracesResponse':
        return await self._unary_unary(
            '/ibc.applications.transfer.v1.Query/DenomTraces',
            query_denom_traces_request,
            QueryDenomTracesResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def params(
        self,
        query_params_request: 'QueryParamsRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'QueryParamsResponse':
        return await self._unary_unary(
            '/ibc.applications.transfer.v1.Query/Params',
            query_params_request,
            QueryParamsResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def denom_hash(
        self,
        query_denom_hash_request: 'QueryDenomHashRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'QueryDenomHashResponse':
        return await self._unary_unary(
            '/ibc.applications.transfer.v1.Query/DenomHash',
            query_denom_hash_request,
            QueryDenomHashResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )


class MsgStub(betterproto.ServiceStub):
    async def transfer(
        self,
        msg_transfer: 'MsgTransfer',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'MsgTransferResponse':
        return await self._unary_unary(
            '/ibc.applications.transfer.v1.Msg/Transfer',
            msg_transfer,
            MsgTransferResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )


class QueryBase(ServiceBase):
    async def denom_trace(
        self, query_denom_trace_request: 'QueryDenomTraceRequest'
    ) -> 'QueryDenomTraceResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def denom_traces(
        self, query_denom_traces_request: 'QueryDenomTracesRequest'
    ) -> 'QueryDenomTracesResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def params(
        self, query_params_request: 'QueryParamsRequest'
    ) -> 'QueryParamsResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def denom_hash(
        self, query_denom_hash_request: 'QueryDenomHashRequest'
    ) -> 'QueryDenomHashResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def __rpc_denom_trace(
        self,
        stream: 'grpclib.server.Stream[QueryDenomTraceRequest, QueryDenomTraceResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.denom_trace(request)
        await stream.send_message(response)

    async def __rpc_denom_traces(
        self,
        stream: 'grpclib.server.Stream[QueryDenomTracesRequest, QueryDenomTracesResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.denom_traces(request)
        await stream.send_message(response)

    async def __rpc_params(
        self, stream: 'grpclib.server.Stream[QueryParamsRequest, QueryParamsResponse]'
    ) -> None:
        request = await stream.recv_message()
        response = await self.params(request)
        await stream.send_message(response)

    async def __rpc_denom_hash(
        self,
        stream: 'grpclib.server.Stream[QueryDenomHashRequest, QueryDenomHashResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.denom_hash(request)
        await stream.send_message(response)

    def __mapping__(self) -> dict[str, grpclib.const.Handler]:
        return {
            '/ibc.applications.transfer.v1.Query/DenomTrace': grpclib.const.Handler(
                self.__rpc_denom_trace,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryDenomTraceRequest,
                QueryDenomTraceResponse,
            ),
            '/ibc.applications.transfer.v1.Query/DenomTraces': grpclib.const.Handler(
                self.__rpc_denom_traces,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryDenomTracesRequest,
                QueryDenomTracesResponse,
            ),
            '/ibc.applications.transfer.v1.Query/Params': grpclib.const.Handler(
                self.__rpc_params,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryParamsRequest,
                QueryParamsResponse,
            ),
            '/ibc.applications.transfer.v1.Query/DenomHash': grpclib.const.Handler(
                self.__rpc_denom_hash,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryDenomHashRequest,
                QueryDenomHashResponse,
            ),
        }


class MsgBase(ServiceBase):
    async def transfer(self, msg_transfer: 'MsgTransfer') -> 'MsgTransferResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def __rpc_transfer(
        self, stream: 'grpclib.server.Stream[MsgTransfer, MsgTransferResponse]'
    ) -> None:
        request = await stream.recv_message()
        response = await self.transfer(request)
        await stream.send_message(response)

    def __mapping__(self) -> dict[str, grpclib.const.Handler]:
        return {
            '/ibc.applications.transfer.v1.Msg/Transfer': grpclib.const.Handler(
                self.__rpc_transfer,
                grpclib.const.Cardinality.UNARY_UNARY,
                MsgTransfer,
                MsgTransferResponse,
            ),
        }
