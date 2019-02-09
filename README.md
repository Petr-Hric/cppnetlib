# cppnetlib
cppnetlib is lightweight C++14 socket wrapper with very basic server/client implementation

Support: \
Linux / Windows \
IPV4 / IPV6 \
TCP / UDP

Sample code:
```c++
#include "cppnetlib/cppnetlib.h"

#include <iostream>
#include <thread>

using namespace cppnetlib;

std::function<void(client::ClientBase<IPProto::TCP>&&, Address&&)>
    onAccept([](client::ClientBase<IPProto::TCP>&& client, Address&& address) {
    static const std::string welcomeMessage = "Welcome to cppnetlib server!";

    const error::ExpectedValue<std::size_t, error::IOReturnValue> sent =
        client.send(reinterpret_cast<const TransmitDataT*>(welcomeMessage.c_str()), welcomeMessage.size());
    if (!sent.hasError()) {
        std::cout << "[ServerSide]: Welcome message successfuly sent to "
            << address.ip() << ":" << address.port() << "\n";
    } else {
        std::clog << "[ServerSide]: Error occured during sending data\n";
    }
});

void clientThread() {
    client::Client<IPProto::TCP> client(IPVer::IPv4);

    client.openSocket();
    client.connect({IPVer::IPv4, "127.0.0.1", 25565U});

    char dataBuffer[1024] = {};
    const error::ExpectedValue<std::size_t, error::IOReturnValue> received =
        client.receive(reinterpret_cast<TransmitDataT*>(dataBuffer), sizeof(dataBuffer) - 1U).value();
    if (!received.hasError()) {
        std::cout << "[ClientSide]: Received message (Length: " << received.value() << ") - "
            << dataBuffer << '\n';
    } else {
        std::clog << "[ClientSide]: Error occured during receiving data\n";
    }
}

int main() {
    server::Server<IPProto::TCP> server(IPVer::IPv4);
    server.openSocket();
    server.bind({ IPVer::IPv4, "127.0.0.1", 25565U });
    server.listen(255U);

    std::thread t = std::thread(clientThread);

    server.tryAccept(onAccept);

    t.join();

    return 0;
}
```
