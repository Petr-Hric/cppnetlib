#include "cppnetlib/cppnetlib.h"

#include <iostream>
#include <thread>

using namespace cppnetlib;

std::function<void(client::ClientBase<IPProto::TCP>&&, Address&&)>
    onAccept([](client::ClientBase<IPProto::TCP>&& client, Address&& address) {
        static const std::string welcomeMessage = "Welcome to cppnetlib server!";

        std::cout << "[ServerSide]: Client " << address.ip() << ":" << address.port() << " connected!\n"
                  << "[ServerSide]: Sending welcome message to " << address.ip() << ":" << address.port()
                  << " ...\n";

        const error::ExpectedValue<std::size_t, error::IOReturnValue> sent = client.send(
            reinterpret_cast<const TransmitDataT*>(welcomeMessage.c_str()), welcomeMessage.size());
        if (!sent.hasError()) {
            std::cout << "[ServerSide]: Welcome message successfuly sent to " << address.ip() << ":"
                      << address.port() << "\n";
        } else {
            std::clog << "[ServerSide]: Error occured during sending data\n";
        }
    });

void clientThread() {
    client::Client<IPProto::TCP> client(IPVer::IPv4);

    const Address address(IPVer::IPv4, "127.0.0.1", 25565U);

    std::cout << "[ClientSide]: Connecting to " << address.ip() << ":" << address.port() << " ...\n";

    client.openSocket();
    client.connect(address);

    char dataBuffer[1024] = {};
    const error::ExpectedValue<std::size_t, error::IOReturnValue> received =
        client.receive(reinterpret_cast<TransmitDataT*>(dataBuffer), sizeof(dataBuffer) - 1U).value();
    if (!received.hasError()) {
        std::cout << "[ClientSide]: Received message (Length: " << received.value() << ") - " << dataBuffer
                  << '\n';
    } else {
        std::clog << "[ClientSide]: Error occured during receiving data\n";
    }
}

int main() {
    server::Server<IPProto::TCP> server(IPVer::IPv4);
    server.openSocket();
    server.bind({ IPVer::IPv4, "127.0.0.1", 25565U });
    server.listen(255U);

    std::cout << "[ServerSize]: Ready. Waiting for incomming connection ...\n";

    std::thread t = std::thread(clientThread);

    server.tryAccept(onAccept);

    t.join();

    return 0;
};