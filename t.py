from __future__ import annotations

import asyncio
from dataclasses import dataclass as std_dataclass

import GNServer
from GNServer import DataModel, Field, GNRequest, GNResponse, Url, response
from gnobjects.net.base_model import DataModelValidationError, model_validate
from gnobjects.net.objects import DMPContainer
from pydantic import BaseModel as PydanticModel


class PydanticUser(PydanticModel):
    user_id: int
    email: str


@std_dataclass(slots=True)
class DataUser:
    user_id: int
    email: str


class CreateUser(DataModel):
    email: str = Field(max_bytes=128)
    age: int = Field(min=18, max=120)
    tags: list[str] = Field(max_len=16)


data_dict: dict = CreateUser("a@b.c", 18, []).model.toDict()

from_dict: CreateUser = CreateUser.model.fromDict(data_dict)


class CreateUserResult(DataModel):
    user_id: int
    nick: str
    created: bool


app = GNServer.App()


@app.post("/users/create")
async def create_user(body: CreateUser) -> GNResponse:
    nick = body.email.split("@", 1)[0]
    return response.ok(CreateUserResult(user_id=1001, nick=nick, created=True))


async def main() -> None:
    request = GNRequest(
        "post",
        Url("gn://example.gn/users/create"),
        payload=CreateUser(email="alice@example.com", age=30, tags=["admin"]),
    )
    request_container = (await request.tdo).container
    assert isinstance(request_container, DMPContainer)
    print(request_container.schema_name, request_container.payload)

    body = model_validate(CreateUser, request_container.payload)
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
        model_validate(CreateUser, {"email": "bad@example.com", "age": "30", "tags": []})
    except DataModelValidationError as exc:
        print("DataModel strict check:", exc)


asyncio.run(main())
