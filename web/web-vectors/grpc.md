---
description: >-
  gRPC is a modern open source high performance Remote Procedure Call (RPC)
  framework that can run in any environment.
---

# gRPC

{% embed url="https://www.youtube.com/watch?ab_channel=gRPC&v=njC24ts24Pg" %}

### What is gRPC?

gRPC or (Google Remote Procedure Call) is a high-performance, open-source, remote procedure call (RPC) framework developed by Google. It allows applications to communicate with each other over a network in a client-server model by invoking methods on a remote server as if they were local functions. gRPC is built on top of HTTP/2 and uses Protocol Buffers (protobufs) as its interface definition language (IDL) for defining service methods and message types.

{% hint style="info" %}
gRPC uses Protocol Buffers to serialize structured data, much like JSON only smaller and faster and wil only run over http/2 with TLS.
{% endhint %}

### Protocol Buffers

Protocol buffers are like a contract for communication or schema. Traditionally with an API, you dont necessaraliy have a API contract that is definied by the protocol itself. If using REST for example you are sending JSON messages with key:value pairs, that are not checked until you get to the receiving end.

In the proto file for the protocol buffer you can:

```json
message Person {
  required string name = 1;
  optional int32 id = 2;
  optional string email  = 3;
}
```

Also define:

* which fields you expect
* which fiels are required
* object types for those fields.
* Defining which procedures are callable from other microservices.

Finally if you run the proto file against a compiler the output will be in source code in your chosen language for example Python.

<details>

<summary>Example proto file</summary>

{% code overflow="wrap" %}
```json
syntax = "proto3";

option csharp_namespace = "InventoryProductService";

package greet;

// The greeting service definition.
service InventoryProductGRPC {
  // get items
  rpc GetItems (HelloRequest) returns (ItemList);
}

// The request message containing the user's name.
message HelloRequest {
  string name = 1;
}

// The response message containing the greetings.
message HelloReply {
  string message = 1;
}

message Item {
 string name = 1;
 int64 units = 2;
 int64 price = 3;
}
message ItemList {
 repeated Item items = 1;
}
```
{% endcode %}

</details>

### gRPCurl

{% hint style="info" %}
I used this box with a gRPC vulnerability. [https://www.hackthebox.com/machines/pc](https://www.hackthebox.com/machines/pc)
{% endhint %}

`grpcurl` is a command-line tool that lets you interact with gRPC servers. It's basically `curl` for gRPC servers. You can download it here [gRPCurl](https://github.com/fullstorydev/grpcurl) or `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`

Or you can use a docker container

```bash
docker pull fullstorydev/grpcurl:latest
```

Expose services

```bash
$ sudo docker run fullstorydev/grpcurl -plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

Check method in that service

```bash
$ sudo docker run fullstorydev/grpcurl -plaintext 10.10.11.214:50051 list grpc.reflection.v1alpha.ServerReflection
grpc.reflection.v1alpha.ServerReflection.ServerReflectionInfo
```

Using describe wil get the contract for that service

{% code overflow="wrap" %}
```bash
$ sudo docker run fullstorydev/grpcurl -plaintext 10.10.11.214:50051 describe SimpleApp                               
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
```
{% endcode %}

Thi service has 3 methods:

* LoginUser (takes in `LoginUserRequest`)
* RegisterUser (takes in `RegisterUserRequest`)
* getInfo (takes in `GetInfoRequest`)

Lets register a user:

```bash
$ sudo docker run fullstorydev/grpcurl -plaintext 10.10.11.214:50051 SimpleApp.RegisterUser
{
  "message": "username or password must be greater than 4"
}
```

We have to include the username and password using gRPC format similar to JSON.

{% code overflow="wrap" %}
```bash
sudo docker run fullstorydev/grpcurl -plaintext -d '{"username": "mczen", "password": "mczen"}' 10.10.11.214:50051 SimpleApp/RegisterUser
{
  "message": "Account created for user mczen!"
}
```
{% endcode %}

This time we get the message back a user is created. Login in initially only returd an id value but running the command with a verbose flag returned a token which was need to execute the `getInfo` method.

{% code overflow="wrap" %}
```bash
$ sudo docker run fullstorydev/grpcurl -d 'username: "mczen2", password: "mczen2"' -plaintext -format text 10.10.11.214:50051 SimpleApp.LoginUser
message: "Your id is 379."
                                                                                                                                                                                                                        
┌──(kali㉿kali)-[~/Desktop]
└─$ sudo docker run fullstorydev/grpcurl -v -d 'username: "mczen2", password: "mczen2"' -plaintext -format text 10.10.11.214:50051 SimpleApp.LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
message: "Your id is 453."

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibWN6ZW4yIiwiZXhwIjoxNzMwOTg4MTk1fQ.7e2RMUCNCucLCNUsgoFLlOQJqfei78-aT5XfAoXzyAE'
Sent 1 request and received 1 response
```
{% endcode %}

Using the token and id we call getInfo:

```bash
$ sudo docker run fullstorydev/grpcurl -d 'id: "453"' -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibWN6ZW4yIiwiZXhwIjoxNzMwOTg4MTk1fQ.7e2RMUCNCucLCNUsgoFLlOQJqfei78-aT5XfAoXzyAE" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
```

Calling the getInfo method we get back "Will update soon". Checking the id parameter we get back <`class 'sqlite3.Warning'>` . Lets check for sql in jection in the `id` parameter.

{% content-ref url="union-sql-injection.md" %}
[union-sql-injection.md](union-sql-injection.md)
{% endcontent-ref %}
