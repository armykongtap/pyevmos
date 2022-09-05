from __future__ import annotations

# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: cosmos/base/tendermint/v1beta1/query.proto
# plugin: python-betterproto
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

import betterproto
import betterproto.lib.google.protobuf as betterproto_lib_google_protobuf
import grpclib
from betterproto.grpc.grpclib_server import ServiceBase

from .....tendermint import p2p as ____tendermint_p2_p__
from .....tendermint import types as ____tendermint_types__
from ...query import v1beta1 as __query_v1_beta1__

if TYPE_CHECKING:
    import grpclib.server
    from betterproto.grpc.grpclib_client import MetadataLike
    from grpclib.metadata import Deadline


@dataclass(eq=False, repr=False)
class GetValidatorSetByHeightRequest(betterproto.Message):
    """
    GetValidatorSetByHeightRequest is the request type for the
    Query/GetValidatorSetByHeight RPC method.
    """

    height: int = betterproto.int64_field(1)
    pagination: __query_v1_beta1__.PageRequest = betterproto.message_field(2)
    """pagination defines an pagination for the request."""


@dataclass(eq=False, repr=False)
class GetValidatorSetByHeightResponse(betterproto.Message):
    """
    GetValidatorSetByHeightResponse is the response type for the
    Query/GetValidatorSetByHeight RPC method.
    """

    block_height: int = betterproto.int64_field(1)
    validators: list[Validator] = betterproto.message_field(2)
    pagination: __query_v1_beta1__.PageResponse = betterproto.message_field(3)
    """pagination defines an pagination for the response."""


@dataclass(eq=False, repr=False)
class GetLatestValidatorSetRequest(betterproto.Message):
    """
    GetLatestValidatorSetRequest is the request type for the
    Query/GetValidatorSetByHeight RPC method.
    """

    pagination: __query_v1_beta1__.PageRequest = betterproto.message_field(1)
    """pagination defines an pagination for the request."""


@dataclass(eq=False, repr=False)
class GetLatestValidatorSetResponse(betterproto.Message):
    """
    GetLatestValidatorSetResponse is the response type for the
    Query/GetValidatorSetByHeight RPC method.
    """

    block_height: int = betterproto.int64_field(1)
    validators: list[Validator] = betterproto.message_field(2)
    pagination: __query_v1_beta1__.PageResponse = betterproto.message_field(3)
    """pagination defines an pagination for the response."""


@dataclass(eq=False, repr=False)
class Validator(betterproto.Message):
    """Validator is the type for the validator-set."""

    address: str = betterproto.string_field(1)
    pub_key: betterproto_lib_google_protobuf.Any = betterproto.message_field(2)
    voting_power: int = betterproto.int64_field(3)
    proposer_priority: int = betterproto.int64_field(4)


@dataclass(eq=False, repr=False)
class GetBlockByHeightRequest(betterproto.Message):
    """
    GetBlockByHeightRequest is the request type for the Query/GetBlockByHeight
    RPC method.
    """

    height: int = betterproto.int64_field(1)


@dataclass(eq=False, repr=False)
class GetBlockByHeightResponse(betterproto.Message):
    """
    GetBlockByHeightResponse is the response type for the
    Query/GetBlockByHeight RPC method.
    """

    block_id: ____tendermint_types__.BlockId = betterproto.message_field(1)
    block: ____tendermint_types__.Block = betterproto.message_field(2)


@dataclass(eq=False, repr=False)
class GetLatestBlockRequest(betterproto.Message):
    """
    GetLatestBlockRequest is the request type for the Query/GetLatestBlock RPC
    method.
    """

    pass


@dataclass(eq=False, repr=False)
class GetLatestBlockResponse(betterproto.Message):
    """
    GetLatestBlockResponse is the response type for the Query/GetLatestBlock
    RPC method.
    """

    block_id: ____tendermint_types__.BlockId = betterproto.message_field(1)
    block: ____tendermint_types__.Block = betterproto.message_field(2)


@dataclass(eq=False, repr=False)
class GetSyncingRequest(betterproto.Message):
    """
    GetSyncingRequest is the request type for the Query/GetSyncing RPC method.
    """

    pass


@dataclass(eq=False, repr=False)
class GetSyncingResponse(betterproto.Message):
    """
    GetSyncingResponse is the response type for the Query/GetSyncing RPC
    method.
    """

    syncing: bool = betterproto.bool_field(1)


@dataclass(eq=False, repr=False)
class GetNodeInfoRequest(betterproto.Message):
    """
    GetNodeInfoRequest is the request type for the Query/GetNodeInfo RPC
    method.
    """

    pass


@dataclass(eq=False, repr=False)
class GetNodeInfoResponse(betterproto.Message):
    """
    GetNodeInfoResponse is the request type for the Query/GetNodeInfo RPC
    method.
    """

    default_node_info: ____tendermint_p2_p__.DefaultNodeInfo = (
        betterproto.message_field(1)
    )
    application_version: VersionInfo = betterproto.message_field(2)


@dataclass(eq=False, repr=False)
class VersionInfo(betterproto.Message):
    """VersionInfo is the type for the GetNodeInfoResponse message."""

    name: str = betterproto.string_field(1)
    app_name: str = betterproto.string_field(2)
    version: str = betterproto.string_field(3)
    git_commit: str = betterproto.string_field(4)
    build_tags: str = betterproto.string_field(5)
    go_version: str = betterproto.string_field(6)
    build_deps: list[Module] = betterproto.message_field(7)
    cosmos_sdk_version: str = betterproto.string_field(8)
    """Since: cosmos-sdk 0.43"""


@dataclass(eq=False, repr=False)
class Module(betterproto.Message):
    """Module is the type for VersionInfo"""

    path: str = betterproto.string_field(1)
    """module path"""

    version: str = betterproto.string_field(2)
    """module version"""

    sum: str = betterproto.string_field(3)
    """checksum"""


class ServiceStub(betterproto.ServiceStub):
    async def get_node_info(
        self,
        get_node_info_request: 'GetNodeInfoRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'GetNodeInfoResponse':
        return await self._unary_unary(
            '/cosmos.base.tendermint.v1beta1.Service/GetNodeInfo',
            get_node_info_request,
            GetNodeInfoResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_syncing(
        self,
        get_syncing_request: 'GetSyncingRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'GetSyncingResponse':
        return await self._unary_unary(
            '/cosmos.base.tendermint.v1beta1.Service/GetSyncing',
            get_syncing_request,
            GetSyncingResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_latest_block(
        self,
        get_latest_block_request: 'GetLatestBlockRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'GetLatestBlockResponse':
        return await self._unary_unary(
            '/cosmos.base.tendermint.v1beta1.Service/GetLatestBlock',
            get_latest_block_request,
            GetLatestBlockResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_block_by_height(
        self,
        get_block_by_height_request: 'GetBlockByHeightRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'GetBlockByHeightResponse':
        return await self._unary_unary(
            '/cosmos.base.tendermint.v1beta1.Service/GetBlockByHeight',
            get_block_by_height_request,
            GetBlockByHeightResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_latest_validator_set(
        self,
        get_latest_validator_set_request: 'GetLatestValidatorSetRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'GetLatestValidatorSetResponse':
        return await self._unary_unary(
            '/cosmos.base.tendermint.v1beta1.Service/GetLatestValidatorSet',
            get_latest_validator_set_request,
            GetLatestValidatorSetResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_validator_set_by_height(
        self,
        get_validator_set_by_height_request: 'GetValidatorSetByHeightRequest',
        *,
        timeout: float | None = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None,
    ) -> 'GetValidatorSetByHeightResponse':
        return await self._unary_unary(
            '/cosmos.base.tendermint.v1beta1.Service/GetValidatorSetByHeight',
            get_validator_set_by_height_request,
            GetValidatorSetByHeightResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )


class ServiceBase(ServiceBase):
    async def get_node_info(
        self, get_node_info_request: 'GetNodeInfoRequest'
    ) -> 'GetNodeInfoResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_syncing(
        self, get_syncing_request: 'GetSyncingRequest'
    ) -> 'GetSyncingResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_latest_block(
        self, get_latest_block_request: 'GetLatestBlockRequest'
    ) -> 'GetLatestBlockResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_block_by_height(
        self, get_block_by_height_request: 'GetBlockByHeightRequest'
    ) -> 'GetBlockByHeightResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_latest_validator_set(
        self, get_latest_validator_set_request: 'GetLatestValidatorSetRequest'
    ) -> 'GetLatestValidatorSetResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_validator_set_by_height(
        self, get_validator_set_by_height_request: 'GetValidatorSetByHeightRequest'
    ) -> 'GetValidatorSetByHeightResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def __rpc_get_node_info(
        self, stream: 'grpclib.server.Stream[GetNodeInfoRequest, GetNodeInfoResponse]'
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_node_info(request)
        await stream.send_message(response)

    async def __rpc_get_syncing(
        self, stream: 'grpclib.server.Stream[GetSyncingRequest, GetSyncingResponse]'
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_syncing(request)
        await stream.send_message(response)

    async def __rpc_get_latest_block(
        self,
        stream: 'grpclib.server.Stream[GetLatestBlockRequest, GetLatestBlockResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_latest_block(request)
        await stream.send_message(response)

    async def __rpc_get_block_by_height(
        self,
        stream: 'grpclib.server.Stream[GetBlockByHeightRequest, GetBlockByHeightResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_block_by_height(request)
        await stream.send_message(response)

    async def __rpc_get_latest_validator_set(
        self,
        stream: 'grpclib.server.Stream[GetLatestValidatorSetRequest, GetLatestValidatorSetResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_latest_validator_set(request)
        await stream.send_message(response)

    async def __rpc_get_validator_set_by_height(
        self,
        stream: 'grpclib.server.Stream[GetValidatorSetByHeightRequest, GetValidatorSetByHeightResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_validator_set_by_height(request)
        await stream.send_message(response)

    def __mapping__(self) -> dict[str, grpclib.const.Handler]:
        return {
            '/cosmos.base.tendermint.v1beta1.Service/GetNodeInfo': grpclib.const.Handler(
                self.__rpc_get_node_info,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetNodeInfoRequest,
                GetNodeInfoResponse,
            ),
            '/cosmos.base.tendermint.v1beta1.Service/GetSyncing': grpclib.const.Handler(
                self.__rpc_get_syncing,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetSyncingRequest,
                GetSyncingResponse,
            ),
            '/cosmos.base.tendermint.v1beta1.Service/GetLatestBlock': grpclib.const.Handler(
                self.__rpc_get_latest_block,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetLatestBlockRequest,
                GetLatestBlockResponse,
            ),
            '/cosmos.base.tendermint.v1beta1.Service/GetBlockByHeight': grpclib.const.Handler(
                self.__rpc_get_block_by_height,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetBlockByHeightRequest,
                GetBlockByHeightResponse,
            ),
            '/cosmos.base.tendermint.v1beta1.Service/GetLatestValidatorSet': grpclib.const.Handler(
                self.__rpc_get_latest_validator_set,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetLatestValidatorSetRequest,
                GetLatestValidatorSetResponse,
            ),
            '/cosmos.base.tendermint.v1beta1.Service/GetValidatorSetByHeight': grpclib.const.Handler(
                self.__rpc_get_validator_set_by_height,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetValidatorSetByHeightRequest,
                GetValidatorSetByHeightResponse,
            ),
        }
