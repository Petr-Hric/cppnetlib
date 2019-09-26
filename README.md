# cppnetlib

[![Build Status](https://travis-ci.org/Petr-Hric/cppnetlib.svg?branch=master)](https://travis-ci.org/Petr-Hric/cppnetlib)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/8ba99af01ecf45a0a0c6a7a1a61c9b22)](https://www.codacy.com/manual/Petr-Hric/cppnetlib?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Petr-Hric/cppnetlib&amp;utm_campaign=Badge_Grade)

cppnetlib is lightweight C++14 socket wrapper with very basic server/client implementation

Support: \
Linux / Windows \
IPV4 / IPV6 \
TCP / UDP

# example

```cpp
// Server

cppnetlib::server::Server<cppnetlib::IPProto::TCP> server;

server.bind({ "127.0.0.1", 25565 });

server.listen(255);

server.tryAccept([](cppnetlib::client::ClientBase<cppnetlib::IPProto::TCP>&& client, cppnetlib::Address&& address, void*) -> void {
    std::cout << "Client " << address << '\n';
    }, nullptr
);

// Client

cppnetlib::client::Client<cppnetlib::IPProto::TCP> client;

client.connect({ "127.0.0.1", 25565 });
```
