---
description: WebSockets | ws:// | wss:// | Bidirectional | Stateful
---

# WebSockets

### <mark style="color:yellow;">What is a websocket</mark>

A websocket is client-server connect that remains open throughout time through a single TCP/IP socket connection. Just like HTTP it is a communication protocol.

<figure><img src="broken-reference" alt=""><figcaption><p>Source: <a href="https://www.geeksforgeeks.org/">https://www.geeksforgeeks.org/</a></p></figcaption></figure>

* HTTP is unidirectional meaning the client sends a request and the server sends a respone. After the response the connection gets closed. Every request opens a new connections. Its stateless meaning it doesnt retain information about previous requests running on top of TCP.

<details>

<summary>More about HTTP messages</summary>

HTTP messages are ASCII-encoded and include the protocol version (e.g., HTTP/1.1, HTTP/2), methods (GET, POST), headers (e.g., Content-Type, Content-Length), host info, and the body containing the transferred data. Headers typically range from 200 bytes to 2 KB, with an average size of 700–800 bytes. Extensive use of cookies and client-side tools that expand storage can reduce the effective HTTP header payload.

</details>

* WebSocket is bidirectional and works the same like client-server communication. It starts with ws:// or wss://. A websocket is a stateful protocl, the connection between client and server wil remain open, untill one of them closes it, during connection communication takes place.

{% hint style="danger" %}
After client-server handshake the client-server will keep the new connection alive which is know as a WebSocket. We can use it for real-time updated or continuous streams of data.
{% endhint %}

### <mark style="color:yellow;">Comparing HTTP and WebSockets</mark>

| WebSocket                                                                                                                                                                                           | HTTP                                                                                                                                                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WebSocket is a bidirectional communication protocol that enables data exchange between the client and server over a single, persistent connection, which remains open until closed by either party. | HTTP is a unidirectional protocol built on the connection-oriented TCP transport layer. Connections are established using HTTP request methods and are closed once the response is sent. |
| Most real-time applications, such as trading, monitoring, and notification services, use WebSocket to receive data over a single communication channel.                                             | Simple RESTful application uses HTTP protocol which is stateless.                                                                                                                        |
| Frequently updated applications use WebSocket because it is faster than an HTTP connection.                                                                                                         | HTTP is used when retaining a connection for a specific time or reusing it for data transmission is unnecessary. However, it is slower compared to WebSockets.                           |

## Building a WebSocket Client and Server

First install the WebSocket package

```bash
pip install websockets
```

After that we create the WebSocket server

```python
import asyncio
import websockets

async def handle_connection(websocket):
   
   # Print when a client connects, showing their address
   print(f"Client connected from {websocket.remote_address}")
   try:
       
       # Keep connection open and handle messages continuously
       while True:
           
           # Wait for and receive message from client
           message = await websocket.recv()
           print(f"Received from client: {message}")
           
           # Send response back to client
           await websocket.send(f"Server received: {message}")
   except websockets.ConnectionClosed:
       
       # Handle client disconnection gracefully
       print(f"Client {websocket.remote_address} disconnected")


async def main():
   
   # Start websocket server and handle incoming connections
   async with websockets.serve(handle_connection, "localhost", 12345) as server:
       print("WebSocket server started on ws://localhost:12345")

       # Keep server running forever
       await asyncio.Future()  

if __name__ == "__main__":
   # Start the async event loop
   asyncio.run(main())
```

And the client

```bash
import asyncio
import websockets

# Function to handle receiving messages from server
async def receive_messages(websocket):
    try:
        while True:

            # Wait for and print any messages from server
            message = await websocket.recv()
            print(f"Received: {message}")
    except websockets.ConnectionClosed:
        print("Connection closed by server")

# Function to handle sending messages to server
async def send_messages(websocket):
    try:
        while True:

            # Get input from user
            message = input("Enter message (or 'quit' to exit): ")
            if message.lower() == 'quit':
                break
            
            # Send message to server
            await websocket.send(message)
    except websockets.ConnectionClosed:
        print("Connection closed by server")


async def connect_to_server():
    uri = "ws://localhost:12345"

    # Connect to websocket server
    async with websockets.connect(uri) as websocket:

        # Create two tasks: one for receiving, one for sending
        receive_task = asyncio.create_task(receive_messages(websocket))
        send_task = asyncio.create_task(send_messages(websocket))

        # Run both tasks concurrently
        await asyncio.gather(receive_task, send_task)

if __name__ == "__main__":
    # Start the async event loop
    asyncio.run(connect_to_server())
```

Testing the server/client

```bash
└─$ python server.py
WebSocket server started on ws://localhost:12345
Client connected from ('::1', 56376, 0, 0)
Received from client: hi there
Received from client: this works
Client ('::1', 56376, 0, 0) disconnected

┌──(env)─(kali㉿kali)-[~/Scripts/websockets]
└─$ python client.py
Enter message (or 'quit' to exit): hi there
Enter message (or 'quit' to exit): this works
```

Or with wscat

```bash
┌──(env)─(kali㉿kali)-[~/Scripts/websockets]
└─$ wscat -c ws://localhost:12345
Connected (press CTRL+C to quit)
> hello
< Server received: hello
> world
< Server received: world
```
