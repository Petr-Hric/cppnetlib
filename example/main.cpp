#include "cppnetlib.h"

#include <iostream>
#include <thread>
#include <mutex>

using namespace cppnetlib;

std::function<void(client::ClientBase<IPProto::TCP>&&, Address&&)> onAccept([](client::ClientBase<IPProto::TCP>&& client, Address&& address) {
    std::cout << "[ServerSide]: Client " << address.ip() << ":" << address.port() << " connected!" << std::endl;

    static const std::string welcomeMessage = "Welcome to cppnetlib server!";

    std::cout << "[ServerSide]: Sending welcome message to " << address.ip() << ":" << address.port() << " ..." << std::endl;

    client.send(reinterpret_cast<const TransmitDataT*>(welcomeMessage.c_str()), welcomeMessage.size());

    std::cout << "[ServerSide]: Welcome message successfuly sent to " << address.ip() << ":" << address.port() << "" << std::endl;
});

void clientThread() {
    client::Client<IPProto::TCP> client(IPVer::IPv4);

    Address address(IPVer::IPv4, "127.0.0.1", 25565U);

    std::cout << "[ClientSide]: Connecting to " << address.ip() << ":" << address.port() << " ..." << std::endl;

    client.connect(Address{IPVer::IPv4, "127.0.0.1", 25565U});

    char dataBuffer[1024] = {};
    std::size_t received = client.receive(reinterpret_cast<TransmitDataT*>(dataBuffer), sizeof(dataBuffer) - 1U).value();

    std::cout << "[ClientSide]: Received message (" << received << ") - " << dataBuffer << std::endl;
}

int main() {
    server::Server<IPProto::TCP> server(IPVer::IPv4);

    server.bind({IPVer::IPv4, "127.0.0.1", 25565U});
    server.listen(255U);

    std::thread t = std::thread(clientThread);

    std::cout << "[ServerSize]: Ready. Waiting for incomming connection ..." << std::endl;

    server.tryAccept(onAccept);

    t.join();

    std::cin.get();

    return 0;
};