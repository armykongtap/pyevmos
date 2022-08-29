# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: cosmos/base/reflection/v2alpha1/reflection.proto
# plugin: python-betterproto
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional

import betterproto
import grpclib
from betterproto.grpc.grpclib_server import ServiceBase

if TYPE_CHECKING:
    import grpclib.server
    from betterproto.grpc.grpclib_client import MetadataLike
    from grpclib.metadata import Deadline


@dataclass(eq=False, repr=False)
class AppDescriptor(betterproto.Message):
    """AppDescriptor describes a cosmos-sdk based application"""

    authn: 'AuthnDescriptor' = betterproto.message_field(1)
    """
    AuthnDescriptor provides information on how to authenticate transactions on
    the application NOTE: experimental and subject to change in future
    releases.
    """

    chain: 'ChainDescriptor' = betterproto.message_field(2)
    """chain provides the chain descriptor"""

    codec: 'CodecDescriptor' = betterproto.message_field(3)
    """codec provides metadata information regarding codec related types"""

    configuration: 'ConfigurationDescriptor' = betterproto.message_field(4)
    """
    configuration provides metadata information regarding the sdk.Config type
    """

    query_services: 'QueryServicesDescriptor' = betterproto.message_field(5)
    """
    query_services provides metadata information regarding the available
    queriable endpoints
    """

    tx: 'TxDescriptor' = betterproto.message_field(6)
    """
    tx provides metadata information regarding how to send transactions to the
    given application
    """


@dataclass(eq=False, repr=False)
class TxDescriptor(betterproto.Message):
    """TxDescriptor describes the accepted transaction type"""

    fullname: str = betterproto.string_field(1)
    """
    fullname is the protobuf fullname of the raw transaction type (for instance
    the tx.Tx type) it is not meant to support polymorphism of transaction
    types, it is supposed to be used by reflection clients to understand if
    they can handle a specific transaction type in an application.
    """

    msgs: List['MsgDescriptor'] = betterproto.message_field(2)
    """msgs lists the accepted application messages (sdk.Msg)"""


@dataclass(eq=False, repr=False)
class AuthnDescriptor(betterproto.Message):
    """
    AuthnDescriptor provides information on how to sign transactions without
    relying on the online RPCs GetTxMetadata and CombineUnsignedTxAndSignatures
    """

    sign_modes: List['SigningModeDescriptor'] = betterproto.message_field(1)
    """sign_modes defines the supported signature algorithm"""


@dataclass(eq=False, repr=False)
class SigningModeDescriptor(betterproto.Message):
    """
    SigningModeDescriptor provides information on a signing flow of the
    application NOTE(fdymylja): here we could go as far as providing an entire
    flow on how to sign a message given a SigningModeDescriptor, but it's
    better to think about this another time
    """

    name: str = betterproto.string_field(1)
    """name defines the unique name of the signing mode"""

    number: int = betterproto.int32_field(2)
    """number is the unique int32 identifier for the sign_mode enum"""

    authn_info_provider_method_fullname: str = betterproto.string_field(3)
    """
    authn_info_provider_method_fullname defines the fullname of the method to
    call to get the metadata required to authenticate using the provided
    sign_modes
    """


@dataclass(eq=False, repr=False)
class ChainDescriptor(betterproto.Message):
    """ChainDescriptor describes chain information of the application"""

    id: str = betterproto.string_field(1)
    """id is the chain id"""


@dataclass(eq=False, repr=False)
class CodecDescriptor(betterproto.Message):
    """
    CodecDescriptor describes the registered interfaces and provides metadata
    information on the types
    """

    interfaces: List['InterfaceDescriptor'] = betterproto.message_field(1)
    """interfaces is a list of the registerted interfaces descriptors"""


@dataclass(eq=False, repr=False)
class InterfaceDescriptor(betterproto.Message):
    """InterfaceDescriptor describes the implementation of an interface"""

    fullname: str = betterproto.string_field(1)
    """fullname is the name of the interface"""

    interface_accepting_messages: List[
        'InterfaceAcceptingMessageDescriptor'
    ] = betterproto.message_field(2)
    """
    interface_accepting_messages contains information regarding the proto
    messages which contain the interface as google.protobuf.Any field
    """

    interface_implementers: List[
        'InterfaceImplementerDescriptor'
    ] = betterproto.message_field(3)
    """
    interface_implementers is a list of the descriptors of the interface
    implementers
    """


@dataclass(eq=False, repr=False)
class InterfaceImplementerDescriptor(betterproto.Message):
    """InterfaceImplementerDescriptor describes an interface implementer"""

    fullname: str = betterproto.string_field(1)
    """fullname is the protobuf queryable name of the interface implementer"""

    type_url: str = betterproto.string_field(2)
    """
    type_url defines the type URL used when marshalling the type as any this is
    required so we can provide type safe google.protobuf.Any marshalling and
    unmarshalling, making sure that we don't accept just 'any' type in our
    interface fields
    """


@dataclass(eq=False, repr=False)
class InterfaceAcceptingMessageDescriptor(betterproto.Message):
    """
    InterfaceAcceptingMessageDescriptor describes a protobuf message which
    contains an interface represented as a google.protobuf.Any
    """

    fullname: str = betterproto.string_field(1)
    """
    fullname is the protobuf fullname of the type containing the interface
    """

    field_descriptor_names: List[str] = betterproto.string_field(2)
    """
    field_descriptor_names is a list of the protobuf name (not fullname) of the
    field which contains the interface as google.protobuf.Any (the interface is
    the same, but it can be in multiple fields of the same proto message)
    """


@dataclass(eq=False, repr=False)
class ConfigurationDescriptor(betterproto.Message):
    """
    ConfigurationDescriptor contains metadata information on the sdk.Config
    """

    bech32_account_address_prefix: str = betterproto.string_field(1)
    """bech32_account_address_prefix is the account address prefix"""


@dataclass(eq=False, repr=False)
class MsgDescriptor(betterproto.Message):
    """
    MsgDescriptor describes a cosmos-sdk message that can be delivered with a
    transaction
    """

    msg_type_url: str = betterproto.string_field(1)
    """msg_type_url contains the TypeURL of a sdk.Msg."""


@dataclass(eq=False, repr=False)
class GetAuthnDescriptorRequest(betterproto.Message):
    """
    GetAuthnDescriptorRequest is the request used for the GetAuthnDescriptor
    RPC
    """

    pass


@dataclass(eq=False, repr=False)
class GetAuthnDescriptorResponse(betterproto.Message):
    """
    GetAuthnDescriptorResponse is the response returned by the
    GetAuthnDescriptor RPC
    """

    authn: 'AuthnDescriptor' = betterproto.message_field(1)
    """
    authn describes how to authenticate to the application when sending
    transactions
    """


@dataclass(eq=False, repr=False)
class GetChainDescriptorRequest(betterproto.Message):
    """
    GetChainDescriptorRequest is the request used for the GetChainDescriptor
    RPC
    """

    pass


@dataclass(eq=False, repr=False)
class GetChainDescriptorResponse(betterproto.Message):
    """
    GetChainDescriptorResponse is the response returned by the
    GetChainDescriptor RPC
    """

    chain: 'ChainDescriptor' = betterproto.message_field(1)
    """chain describes application chain information"""


@dataclass(eq=False, repr=False)
class GetCodecDescriptorRequest(betterproto.Message):
    """
    GetCodecDescriptorRequest is the request used for the GetCodecDescriptor
    RPC
    """

    pass


@dataclass(eq=False, repr=False)
class GetCodecDescriptorResponse(betterproto.Message):
    """
    GetCodecDescriptorResponse is the response returned by the
    GetCodecDescriptor RPC
    """

    codec: 'CodecDescriptor' = betterproto.message_field(1)
    """
    codec describes the application codec such as registered interfaces and
    implementations
    """


@dataclass(eq=False, repr=False)
class GetConfigurationDescriptorRequest(betterproto.Message):
    """
    GetConfigurationDescriptorRequest is the request used for the
    GetConfigurationDescriptor RPC
    """

    pass


@dataclass(eq=False, repr=False)
class GetConfigurationDescriptorResponse(betterproto.Message):
    """
    GetConfigurationDescriptorResponse is the response returned by the
    GetConfigurationDescriptor RPC
    """

    config: 'ConfigurationDescriptor' = betterproto.message_field(1)
    """config describes the application's sdk.Config"""


@dataclass(eq=False, repr=False)
class GetQueryServicesDescriptorRequest(betterproto.Message):
    """
    GetQueryServicesDescriptorRequest is the request used for the
    GetQueryServicesDescriptor RPC
    """

    pass


@dataclass(eq=False, repr=False)
class GetQueryServicesDescriptorResponse(betterproto.Message):
    """
    GetQueryServicesDescriptorResponse is the response returned by the
    GetQueryServicesDescriptor RPC
    """

    queries: 'QueryServicesDescriptor' = betterproto.message_field(1)
    """queries provides information on the available queryable services"""


@dataclass(eq=False, repr=False)
class GetTxDescriptorRequest(betterproto.Message):
    """
    GetTxDescriptorRequest is the request used for the GetTxDescriptor RPC
    """

    pass


@dataclass(eq=False, repr=False)
class GetTxDescriptorResponse(betterproto.Message):
    """
    GetTxDescriptorResponse is the response returned by the GetTxDescriptor RPC
    """

    tx: 'TxDescriptor' = betterproto.message_field(1)
    """
    tx provides information on msgs that can be forwarded to the application
    alongside the accepted transaction protobuf type
    """


@dataclass(eq=False, repr=False)
class QueryServicesDescriptor(betterproto.Message):
    """
    QueryServicesDescriptor contains the list of cosmos-sdk queriable services
    """

    query_services: List['QueryServiceDescriptor'] = betterproto.message_field(1)
    """query_services is a list of cosmos-sdk QueryServiceDescriptor"""


@dataclass(eq=False, repr=False)
class QueryServiceDescriptor(betterproto.Message):
    """QueryServiceDescriptor describes a cosmos-sdk queryable service"""

    fullname: str = betterproto.string_field(1)
    """fullname is the protobuf fullname of the service descriptor"""

    is_module: bool = betterproto.bool_field(2)
    """
    is_module describes if this service is actually exposed by an application's
    module
    """

    methods: List['QueryMethodDescriptor'] = betterproto.message_field(3)
    """methods provides a list of query service methods"""


@dataclass(eq=False, repr=False)
class QueryMethodDescriptor(betterproto.Message):
    """
    QueryMethodDescriptor describes a queryable method of a query service no
    other info is provided beside method name and tendermint queryable path
    because it would be redundant with the grpc reflection service
    """

    name: str = betterproto.string_field(1)
    """name is the protobuf name (not fullname) of the method"""

    full_query_path: str = betterproto.string_field(2)
    """
    full_query_path is the path that can be used to query this method via
    tendermint abci.Query
    """


class ReflectionServiceStub(betterproto.ServiceStub):
    async def get_authn_descriptor(
        self,
        get_authn_descriptor_request: 'GetAuthnDescriptorRequest',
        *,
        timeout: Optional[float] = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None
    ) -> 'GetAuthnDescriptorResponse':
        return await self._unary_unary(
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetAuthnDescriptor',
            get_authn_descriptor_request,
            GetAuthnDescriptorResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_chain_descriptor(
        self,
        get_chain_descriptor_request: 'GetChainDescriptorRequest',
        *,
        timeout: Optional[float] = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None
    ) -> 'GetChainDescriptorResponse':
        return await self._unary_unary(
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetChainDescriptor',
            get_chain_descriptor_request,
            GetChainDescriptorResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_codec_descriptor(
        self,
        get_codec_descriptor_request: 'GetCodecDescriptorRequest',
        *,
        timeout: Optional[float] = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None
    ) -> 'GetCodecDescriptorResponse':
        return await self._unary_unary(
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetCodecDescriptor',
            get_codec_descriptor_request,
            GetCodecDescriptorResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_configuration_descriptor(
        self,
        get_configuration_descriptor_request: 'GetConfigurationDescriptorRequest',
        *,
        timeout: Optional[float] = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None
    ) -> 'GetConfigurationDescriptorResponse':
        return await self._unary_unary(
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetConfigurationDescriptor',
            get_configuration_descriptor_request,
            GetConfigurationDescriptorResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_query_services_descriptor(
        self,
        get_query_services_descriptor_request: 'GetQueryServicesDescriptorRequest',
        *,
        timeout: Optional[float] = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None
    ) -> 'GetQueryServicesDescriptorResponse':
        return await self._unary_unary(
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetQueryServicesDescriptor',
            get_query_services_descriptor_request,
            GetQueryServicesDescriptorResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )

    async def get_tx_descriptor(
        self,
        get_tx_descriptor_request: 'GetTxDescriptorRequest',
        *,
        timeout: Optional[float] = None,
        deadline: Optional['Deadline'] = None,
        metadata: Optional['MetadataLike'] = None
    ) -> 'GetTxDescriptorResponse':
        return await self._unary_unary(
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetTxDescriptor',
            get_tx_descriptor_request,
            GetTxDescriptorResponse,
            timeout=timeout,
            deadline=deadline,
            metadata=metadata,
        )


class ReflectionServiceBase(ServiceBase):
    async def get_authn_descriptor(
        self, get_authn_descriptor_request: 'GetAuthnDescriptorRequest'
    ) -> 'GetAuthnDescriptorResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_chain_descriptor(
        self, get_chain_descriptor_request: 'GetChainDescriptorRequest'
    ) -> 'GetChainDescriptorResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_codec_descriptor(
        self, get_codec_descriptor_request: 'GetCodecDescriptorRequest'
    ) -> 'GetCodecDescriptorResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_configuration_descriptor(
        self, get_configuration_descriptor_request: 'GetConfigurationDescriptorRequest'
    ) -> 'GetConfigurationDescriptorResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_query_services_descriptor(
        self, get_query_services_descriptor_request: 'GetQueryServicesDescriptorRequest'
    ) -> 'GetQueryServicesDescriptorResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def get_tx_descriptor(
        self, get_tx_descriptor_request: 'GetTxDescriptorRequest'
    ) -> 'GetTxDescriptorResponse':
        raise grpclib.GRPCError(grpclib.const.Status.UNIMPLEMENTED)

    async def __rpc_get_authn_descriptor(
        self,
        stream: 'grpclib.server.Stream[GetAuthnDescriptorRequest, GetAuthnDescriptorResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_authn_descriptor(request)
        await stream.send_message(response)

    async def __rpc_get_chain_descriptor(
        self,
        stream: 'grpclib.server.Stream[GetChainDescriptorRequest, GetChainDescriptorResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_chain_descriptor(request)
        await stream.send_message(response)

    async def __rpc_get_codec_descriptor(
        self,
        stream: 'grpclib.server.Stream[GetCodecDescriptorRequest, GetCodecDescriptorResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_codec_descriptor(request)
        await stream.send_message(response)

    async def __rpc_get_configuration_descriptor(
        self,
        stream: 'grpclib.server.Stream[GetConfigurationDescriptorRequest, GetConfigurationDescriptorResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_configuration_descriptor(request)
        await stream.send_message(response)

    async def __rpc_get_query_services_descriptor(
        self,
        stream: 'grpclib.server.Stream[GetQueryServicesDescriptorRequest, GetQueryServicesDescriptorResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_query_services_descriptor(request)
        await stream.send_message(response)

    async def __rpc_get_tx_descriptor(
        self,
        stream: 'grpclib.server.Stream[GetTxDescriptorRequest, GetTxDescriptorResponse]',
    ) -> None:
        request = await stream.recv_message()
        response = await self.get_tx_descriptor(request)
        await stream.send_message(response)

    def __mapping__(self) -> Dict[str, grpclib.const.Handler]:
        return {
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetAuthnDescriptor': grpclib.const.Handler(
                self.__rpc_get_authn_descriptor,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetAuthnDescriptorRequest,
                GetAuthnDescriptorResponse,
            ),
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetChainDescriptor': grpclib.const.Handler(
                self.__rpc_get_chain_descriptor,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetChainDescriptorRequest,
                GetChainDescriptorResponse,
            ),
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetCodecDescriptor': grpclib.const.Handler(
                self.__rpc_get_codec_descriptor,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetCodecDescriptorRequest,
                GetCodecDescriptorResponse,
            ),
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetConfigurationDescriptor': grpclib.const.Handler(
                self.__rpc_get_configuration_descriptor,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetConfigurationDescriptorRequest,
                GetConfigurationDescriptorResponse,
            ),
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetQueryServicesDescriptor': grpclib.const.Handler(
                self.__rpc_get_query_services_descriptor,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetQueryServicesDescriptorRequest,
                GetQueryServicesDescriptorResponse,
            ),
            '/cosmos.base.reflection.v2alpha1.ReflectionService/GetTxDescriptor': grpclib.const.Handler(
                self.__rpc_get_tx_descriptor,
                grpclib.const.Cardinality.UNARY_UNARY,
                GetTxDescriptorRequest,
                GetTxDescriptorResponse,
            ),
        }