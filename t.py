from __future__ import annotations

import asyncio

import GNServer
from GNServer import BaseModel, FastDataModel, GNRequest, GNResponse, Url, response
from gnobjects.net.base_model import FastDataModelValidationError, model_validate
from gnobjects.net.objects import DMPContainer
from pydantic import BaseModel as PydanticBaseModel


class PydanticUser(PydanticBaseModel):
    user_id: int
    email: str


@BaseModel
class DataUser:
    user_id: int
    email: str


@FastDataModel
class FastCreateUser:
    email: str
    age: int
    tags: list[str]


@FastDataModel
class FastCreateUserResult:
    user_id: int
    nick: str
    created: bool


app = GNServer.App()



@app.post("/users/create")
async def create_user(body: FastCreateUser) -> GNResponse:
    nick = body.email.split("@", 1)[0]
    return response.ok(FastCreateUserResult(user_id=1001, nick=nick, created=True))


async def main() -> None:
    request = GNRequest(
        "post",
        Url("gn://example.gn/users/create"),
        payload=FastCreateUser(email="alice@example.com", age=30, tags=["admin"]),
    )
    request_container = (await request.tdo).container
    assert isinstance(request_container, DMPContainer)
    print(request_container.schema_name, request_container.payload)

    body = model_validate(FastCreateUser, request_container.payload)
    server_response = await create_user(body)
    response_container = (await server_response.tdo).container
    assert isinstance(response_container, DMPContainer)
    print(response_container.schema_name, response_container.payload)

    pydantic_request = GNRequest(
        "post",
        Url("gn://example.gn/users/pydantic"),
        payload=PydanticUser(user_id=7, email="bob@example.com"),
    )
    print((await pydantic_request.tdo).container.schema_name)

    dataclass_response = GNResponse("ok", payload=DataUser(user_id=8, email="carol@example.com"))
    print((await dataclass_response.tdo).container.schema_name)

    try:
        model_validate(FastCreateUser, {"email": "bad@example.com", "age": "30", "tags": []})
    except FastDataModelValidationError as exc:
        print("FastDataModel strict check:", exc)


asyncio.run(main())
