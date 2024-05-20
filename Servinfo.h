#pragma once

#include <netdb.h> //freeaddrinfo

class Servinfo
{
private:
    struct addrinfo *data=nullptr;
public:
    Servinfo(){};
    ~Servinfo(){ freeaddrinfo(data); };

    struct addrinfo** operator &() { return &data; }
    operator struct addrinfo*() { return data; }
};