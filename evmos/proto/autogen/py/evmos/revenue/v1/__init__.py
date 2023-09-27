# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: evmos/revenue/v1/genesis.proto, evmos/revenue/v1/query.proto, evmos/revenue/v1/revenue.proto, evmos/revenue/v1/tx.proto
# plugin: python-betterproto
# This file has been @generated
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Dict,
    List,
    Optional,
)

import betterproto
import grpclib
from betterproto.grpc.grpclib_server import ServiceBase

from ....cosmos.base.query import v1beta1 as ___cosmos_base_query_v1_beta1__


if TYPE_CHECKING:
    import grpclib.server
    from betterproto.grpc.grpclib_client import MetadataLike
    from grpclib.metadata import Deadline


@dataclass(eq=False, repr=False)
class Revenue(betterproto.Message):
    """
    Revenue defines an instance that organizes fee distribution conditions for
    the owner of a given smart contract
    """

    contract_address: str = betterproto.string_field(1)
    """hex address of registered contract"""

    deployer_address: str = betterproto.string_field(2)
    """bech32 address of contract deployer"""

    withdrawer_address: str = betterproto.string_field(3)
    """
    bech32 address of account receiving the transaction fees it defaults to
    deployer_address
    """


@dataclass(eq=False, repr=False)
class GenesisState(betterproto.Message):
    """GenesisState defines the module's genesis state."""

    params: "Params" = betterproto.message_field(1)
    """module parameters"""

    revenues: List["Revenue"] = betterproto.message_field(2)
    """active registered contracts for fee distribution"""


@dataclass(eq=False, repr=False)
class Params(betterproto.Message):
    """Params defines the revenue module params"""

    enable_revenue: bool = betterproto.bool_field(1)
    """enable_revenue defines a parameter to enable the revenue module"""

    developer_shares: str = betterproto.string_field(2)
    """
    developer_shares defines the proportion of the transaction fees to be
    distributed to the registered contract owner
    """

    addr_derivation_cost_create: int = betterproto.uint64_field(3)
    """
    addr_derivation_cost_create defines the cost of address derivation for
    verifying the contract deployer at fee registration
    """


@dataclass(eq=False, repr=False)
class QueryRevenuesRequest(betterproto.Message):
    """QueryRevenuesRequest is the request type for the Query/Revenues RPC method."""

    pagination: "___cosmos_base_query_v1_beta1__.PageRequest" = (
        betterproto.message_field(1)
    )
    """pagination defines an optional pagination for the request."""


@dataclass(eq=False, repr=False)
class QueryRevenuesResponse(betterproto.Message):
    """QueryRevenuesResponse is the response type for the Query/Revenues RPC method."""

    revenues: List["Revenue"] = betterproto.message_field(1)
    pagination: "___cosmos_base_query_v1_beta1__.PageResponse" = (
        betterproto.message_field(2)
    )
    """pagination defines the pagination in the response."""


@dataclass(eq=False, repr=False)
class QueryRevenueRequest(betterproto.Message):
    """QueryRevenueRequest is the request type for the Query/Revenue RPC method."""

    contract_address: str = betterproto.string_field(1)
    """contract identifier is the hex contract address of a contract"""


@dataclass(eq=False, repr=False)
class QueryRevenueResponse(betterproto.Message):
    """QueryRevenueResponse is the response type for the Query/Revenue RPC method."""

    revenue: "Revenue" = betterproto.message_field(1)


@dataclass(eq=False, repr=False)
class QueryParamsRequest(betterproto.Message):
    """QueryParamsRequest is the request type for the Query/Params RPC method."""

    pass


@dataclass(eq=False, repr=False)
class QueryParamsResponse(betterproto.Message):
    """QueryParamsResponse is the response type for the Query/Params RPC method."""

    params: "Params" = betterproto.message_field(1)


@dataclass(eq=False, repr=False)
class QueryDeployerRevenuesRequest(betterproto.Message):
    """
    QueryDeployerRevenuesRequest is the request type for the
    Query/DeployerRevenues RPC method.
    """

    deployer_address: str = betterproto.string_field(1)
    """deployer bech32 address"""

    pagination: "___cosmos_base_query_v1_beta1__.PageRequest" = (
        betterproto.message_field(2)
    )
    """pagination defines an optional pagination for the request."""


@dataclass(eq=False, repr=False)
class QueryDeployerRevenuesResponse(betterproto.Message):
    """
    QueryDeployerRevenuesResponse is the response type for the
    Query/DeployerRevenues RPC method.
    """

    contract_addresses: List[str] = betterproto.string_field(1)
    pagination: "___cosmos_base_query_v1_beta1__.PageResponse" = (
        betterproto.message_field(2)
    )
    """pagination defines the pagination in the response."""


@dataclass(eq=False, repr=False)
class QueryWithdrawerRevenuesRequest(betterproto.Message):
    """
    QueryWithdrawerRevenuesRequest is the request type for the
    Query/WithdrawerRevenues RPC method.
    """

    withdrawer_address: str = betterproto.string_field(1)
    """withdrawer bech32 address"""

    pagination: "___cosmos_base_query_v1_beta1__.PageRequest" = (
        betterproto.message_field(2)
    )
    """pagination defines an optional pagination for the request."""


@dataclass(eq=False, repr=False)
class QueryWithdrawerRevenuesResponse(betterproto.Message):
    """
    QueryWithdrawerRevenuesResponse is the response type for the
    Query/WithdrawerRevenues RPC method.
    """

    contract_addresses: List[str] = betterproto.string_field(1)
    pagination: "___cosmos_base_query_v1_beta1__.PageResponse" = (
        betterproto.message_field(2)
    )
    """pagination defines the pagination in the response."""


@dataclass(eq=False, repr=False)
class MsgRegisterRevenue(betterproto.Message):
    """MsgRegisterRevenue defines a message that registers a Revenue"""

    contract_address: str = betterproto.string_field(1)
    """contract hex address"""

    deployer_address: str = betterproto.string_field(2)
    """
    bech32 address of message sender, must be the same as the origin EOA
    sending the transaction which deploys the contract
    """

    withdrawer_address: str = betterproto.string_field(3)
    """bech32 address of account receiving the transaction fees"""

    nonces: List[int] = betterproto.uint64_field(4)
    """
    array of nonces from the address path, where the last nonce is the nonce
    that determines the contract's address - it can be an EOA nonce or a
    factory contract nonce
    """


@dataclass(eq=False, repr=False)
class MsgRegisterRevenueResponse(betterproto.Message):
    """MsgRegisterRevenueResponse defines the MsgRegisterRevenue response type"""

    pass


@dataclass(eq=False, repr=False)
class MsgUpdateRevenue(betterproto.Message):
    """
    MsgUpdateRevenue defines a message that updates the withdrawer address for a
    registered Revenue
    """

    contract_address: str = betterproto.string_field(1)
    """contract hex address"""

    deployer_address: str = betterproto.string_field(2)
    """deployer bech32 address"""

    withdrawer_address: str = betterproto.string_field(3)
    """new withdrawer bech32 address for receiving the transaction fees"""


@dataclass(eq=False, repr=False)
class MsgUpdateRevenueResponse(betterproto.Message):
    """MsgUpdateRevenueResponse defines the MsgUpdateRevenue response type"""

    pass


@dataclass(eq=False, repr=False)
class MsgCancelRevenue(betterproto.Message):
    """MsgCancelRevenue defines a message that cancels a registered Revenue"""

    contract_address: str = betterproto.string_field(1)
    """contract hex address"""

    deployer_address: str = betterproto.string_field(2)
    """deployer bech32 address"""


@dataclass(eq=False, repr=False)
class MsgCancelRevenueResponse(betterproto.Message):
    """MsgCancelRevenueResponse defines the MsgCancelRevenue response type"""

    pass


class QueryStub(betterproto.ServiceStub):
    async def revenues(
        self,
        query_revenues_request: "QueryRevenuesRequest",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "QueryRevenuesResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Query/Revenues",
            query_revenues_request,
            QueryRevenuesResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def revenue(
        self,
        query_revenue_request: "QueryRevenueRequest",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "QueryRevenueResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Query/Revenue",
            query_revenue_request,
            QueryRevenueResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def params(
        self,
        query_params_request: "QueryParamsRequest",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "QueryParamsResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Query/Params",
            query_params_request,
            QueryParamsResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def deployer_revenues(
        self,
        query_deployer_revenues_request: "QueryDeployerRevenuesRequest",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "QueryDeployerRevenuesResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Query/DeployerRevenues",
            query_deployer_revenues_request,
            QueryDeployerRevenuesResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def withdrawer_revenues(
        self,
        query_withdrawer_revenues_request: "QueryWithdrawerRevenuesRequest",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "QueryWithdrawerRevenuesResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Query/WithdrawerRevenues",
            query_withdrawer_revenues_request,
            QueryWithdrawerRevenuesResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )


class MsgStub(betterproto.ServiceStub):
    async def register_revenue(
        self,
        msg_register_revenue: "MsgRegisterRevenue",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "MsgRegisterRevenueResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Msg/RegisterRevenue",
            msg_register_revenue,
            MsgRegisterRevenueResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def update_revenue(
        self,
        msg_update_revenue: "MsgUpdateRevenue",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "MsgUpdateRevenueResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Msg/UpdateRevenue",
            msg_update_revenue,
            MsgUpdateRevenueResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def cancel_revenue(
        self,
        msg_cancel_revenue: "MsgCancelRevenue",
        *,
        timeout: Optional[float] = None,
        deadline: Optional["Deadline"] = None,
        metadata: Optional["MetadataLike"] = None,
    ) -> "MsgCancelRevenueResponse":
        return await self._unary_unary(
            "/evmos.revenue.v1.Msg/CancelRevenue",
            msg_cancel_revenue,
            MsgCancelRevenueResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )


class QueryBase(ServiceBase):
    async def revenues(
        self, query_revenues_request: "QueryRevenuesRequest"
    ) -> "QueryRevenuesResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def revenue(
        self, query_revenue_request: "QueryRevenueRequest"
    ) -> "QueryRevenueResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def params(
        self, query_params_request: "QueryParamsRequest"
    ) -> "QueryParamsResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def deployer_revenues(
        self, query_deployer_revenues_request: "QueryDeployerRevenuesRequest"
    ) -> "QueryDeployerRevenuesResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def withdrawer_revenues(
        self, query_withdrawer_revenues_request: "QueryWithdrawerRevenuesRequest"
    ) -> "QueryWithdrawerRevenuesResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def __rpc_revenues(
        self,
        stream: "grpclib.server.Stream[QueryRevenuesRequest, QueryRevenuesResponse]",
    ) -> None:
        request = await stream.recv_message()
        response = await self.revenues(request)
        await stream.send_message(response)

    async def __rpc_revenue(
        self, stream: "grpclib.server.Stream[QueryRevenueRequest, QueryRevenueResponse]"
    ) -> None:
        request = await stream.recv_message()
        response = await self.revenue(request)
        await stream.send_message(response)

    async def __rpc_params(
        self, stream: "grpclib.server.Stream[QueryParamsRequest, QueryParamsResponse]"
    ) -> None:
        request = await stream.recv_message()
        response = await self.params(request)
        await stream.send_message(response)

    async def __rpc_deployer_revenues(
        self,
        stream: "grpclib.server.Stream[QueryDeployerRevenuesRequest, QueryDeployerRevenuesResponse]",
    ) -> None:
        request = await stream.recv_message()
        response = await self.deployer_revenues(request)
        await stream.send_message(response)

    async def __rpc_withdrawer_revenues(
        self,
        stream: "grpclib.server.Stream[QueryWithdrawerRevenuesRequest, QueryWithdrawerRevenuesResponse]",
    ) -> None:
        request = await stream.recv_message()
        response = await self.withdrawer_revenues(request)
        await stream.send_message(response)

    def __mapping__(self) -> Dict[str, grpclib.const.Handler]:
        return {
            "/evmos.revenue.v1.Query/Revenues": grpclib.const.Handler(
                self.__rpc_revenues,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryRevenuesRequest,
                QueryRevenuesResponse,
            ),
            "/evmos.revenue.v1.Query/Revenue": grpclib.const.Handler(
                self.__rpc_revenue,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryRevenueRequest,
                QueryRevenueResponse,
            ),
            "/evmos.revenue.v1.Query/Params": grpclib.const.Handler(
                self.__rpc_params,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryParamsRequest,
                QueryParamsResponse,
            ),
            "/evmos.revenue.v1.Query/DeployerRevenues": grpclib.const.Handler(
                self.__rpc_deployer_revenues,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryDeployerRevenuesRequest,
                QueryDeployerRevenuesResponse,
            ),
            "/evmos.revenue.v1.Query/WithdrawerRevenues": grpclib.const.Handler(
                self.__rpc_withdrawer_revenues,
                grpclib.const.Cardinality.UNARY_UNARY,
                QueryWithdrawerRevenuesRequest,
                QueryWithdrawerRevenuesResponse,
            ),
        }


class MsgBase(ServiceBase):
    async def register_revenue(
        self, msg_register_revenue: "MsgRegisterRevenue"
    ) -> "MsgRegisterRevenueResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def update_revenue(
        self, msg_update_revenue: "MsgUpdateRevenue"
    ) -> "MsgUpdateRevenueResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def cancel_revenue(
        self, msg_cancel_revenue: "MsgCancelRevenue"
    ) -> "MsgCancelRevenueResponse":
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def __rpc_register_revenue(
        self,
        stream: "grpclib.server.Stream[MsgRegisterRevenue, MsgRegisterRevenueResponse]",
    ) -> None:
        request = await stream.recv_message()
        response = await self.register_revenue(request)
        await stream.send_message(response)

    async def __rpc_update_revenue(
        self,
        stream: "grpclib.server.Stream[MsgUpdateRevenue, MsgUpdateRevenueResponse]",
    ) -> None:
        request = await stream.recv_message()
        response = await self.update_revenue(request)
        await stream.send_message(response)

    async def __rpc_cancel_revenue(
        self,
        stream: "grpclib.server.Stream[MsgCancelRevenue, MsgCancelRevenueResponse]",
    ) -> None:
        request = await stream.recv_message()
        response = await self.cancel_revenue(request)
        await stream.send_message(response)

    def __mapping__(self) -> Dict[str, grpclib.const.Handler]:
        return {
            "/evmos.revenue.v1.Msg/RegisterRevenue": grpclib.const.Handler(
                self.__rpc_register_revenue,
                grpclib.const.Cardinality.UNARY_UNARY,
                MsgRegisterRevenue,
                MsgRegisterRevenueResponse,
            ),
            "/evmos.revenue.v1.Msg/UpdateRevenue": grpclib.const.Handler(
                self.__rpc_update_revenue,
                grpclib.const.Cardinality.UNARY_UNARY,
                MsgUpdateRevenue,
                MsgUpdateRevenueResponse,
            ),
            "/evmos.revenue.v1.Msg/CancelRevenue": grpclib.const.Handler(
                self.__rpc_cancel_revenue,
                grpclib.const.Cardinality.UNARY_UNARY,
                MsgCancelRevenue,
                MsgCancelRevenueResponse,
            ),
        }
