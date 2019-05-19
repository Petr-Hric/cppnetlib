#include <cppnetlib/cppnetlib.h>

#include <iostream>
#include <thread>

using namespace cppnetlib;

void clientThread() {
    try {
        client::Client<IPProto::TCP> client;

        const Address address("127.0.0.1", 25565U);

        std::cout << "[ClientSide]: Connecting to " << address.ip().string() << ":" << address.port()
                  << " ...\n";

        client.connect(address);

        char dataBuffer[1024] = {};
        const error::ExpectedValue<std::size_t, error::IOReturnValue> received =
            client.receive(reinterpret_cast<TransmitDataT*>(dataBuffer), sizeof(dataBuffer) - 1U).value();
        if (!received.hasError()) {
            std::cout << "[ClientSide]: Received message (Length: " << received.value() << ") - "
                      << dataBuffer << '\n';
        } else {
            std::clog << "[ClientSide]: Error occured during receiving data\n";
        }
    } catch (cppnetlib::Exception& e) {
        std::cout << "Exception caught: " << e.message() << std::endl;
    }
}

int main() {
    try {
        static auto onAccept = [](client::ClientBase<IPProto::TCP>&& client, Address&& address) -> void {
            static const std::string welcomeMessage = "Welcome to cppnetlib server!";

            std::cout << "[ServerSide]: Client " << address.ip().string() << ":" << address.port()
                      << " connected!\n"
                      << "[ServerSide]: Sending welcome message to " << address.ip().string() << ":"
                      << address.port() << " ...\n";

            const error::ExpectedValue<std::size_t, error::IOReturnValue> sent = client.send(
                reinterpret_cast<const TransmitDataT*>(welcomeMessage.c_str()), welcomeMessage.size());
            if (!sent.hasError()) {
                std::cout << "[ServerSide]: Welcome message successfuly sent to " << address.ip().string()
                          << ":" << address.port() << "\n";
            } else {
                std::clog << "[ServerSide]: Error occured during sending data\n";
            }
        };

        server::Server<IPProto::TCP> server;
        server.bind({ "127.0.0.1", 25565U });
        server.listen(255U);

        std::cout << "[ServerSide]: Ready. Waiting for incomming connection ...\n";

        std::thread t = std::thread(clientThread);

        server.tryAccept(onAccept);

        t.join();
    } catch (const Exception& e) {
        std::cout << "Exception caught: " << e.message() << std::endl;
    }
    return 0;
};