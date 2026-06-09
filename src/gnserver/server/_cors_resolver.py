import inspect

from gnobjects.net.fastcommands import AllGNFastCommands
from gnobjects.net.objects import GNRequest

from ._models import CORSObject


async def resolve_cors(request: GNRequest, cors: CORSObject | None) -> None:
    if cors is None:
        return

    domain = request.client.domain

    if request.client.type not in cors.allow_client_types and request.client.type_int != 0:
        if cors.except_client_types_domains is None or domain not in cors.except_client_types_domains:
            raise AllGNFastCommands.cors.ClientTypeNotAllowed({'message': f'Client type {request.client.type} not allowed for CORS. Allowed {cors.allow_client_types}'})

    if request.client.type == 'net' and request.object.type not in cors.allow_object_types and request.client.type_int != 0:
        if cors.except_object_types_domains is None or domain not in cors.except_object_types_domains:
            raise AllGNFastCommands.cors.ObjectTypeNotAllowed({'message': f'Object type {request.object.type} not allowed for CORS. Allowed {cors.allow_object_types}'})

    if cors.allowed_domains is not None:
        allowed = True

        if cors._allowed_domains_matcher is not None:
            allowed = cors._allowed_domains_matcher.match_any(domain)

        if allowed and cors._allowed_domains_callback is not None:
            callback_result = cors._allowed_domains_callback(domain)
            if inspect.isawaitable(callback_result):
                callback_result = await callback_result
            allowed = bool(callback_result)

        if not allowed:
            raise AllGNFastCommands.cors.OriginNotAllowed({'message': 'Domain not allowed for CORS', 'domain': domain})

    if cors.allow_methods is not None:
        if request.method not in cors.allow_methods:
            raise AllGNFastCommands.cors.MethodNotAllowed({'message': f'Method {request.method} not allowed for CORS. Allowed {cors.allow_methods}'})

    if cors.allow_transport_protocols is not None:
        if request.transport in ('gn:quik:real', 'gn:quik:dev') and request.transport not in cors.allow_transport_protocols:
            raise AllGNFastCommands.cors.TransportProtocolNotAllowed({'message': 'Transport protocol not allowed for CORS'})
