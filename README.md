# cppnetlib
cppnetlib is lightweight C++14 socket wrapper with very basic server/client implementation

Support: \
Linux / Windows \
IPV4 / IPV6 \
TCP / UDP

Sample code:
```c++
// Client Sample:
void client() {
    client::Client<IPProto::TCP> client(IPVer::IPv4);
    client.openSocket();
    
    client.connect({IPVer::IPv4, "127.0.0.1", 25565U});

    char buffer[1024] = {};
    const error::ExpectedValue<std::size_t, error::IOReturnValue> retv =
    client.receive(reinterpret_cast<TransmitDataT*>(buffer), sizeof(buffer));
    
    client.closeSocket();
}

// Server Sample:
std::function<void(client::ClientBase<IPProto::TCP>&&, Address&&)>
    onAccept([](client::ClientBase<IPProto::TCP>&& client, Address&& address) {
    // Client connected .. do whatever you want!
});

void server() {
    server::Server<IPProto::TCP> server(IPVer::IPv4);
    server.openSocket();
    
    server.bind({ IPVer::IPv4, "127.0.0.1", 25565U });
    server.listen(255U);

    server.tryAccept(onAccept);
    
    server.closeSocket();
}
```
