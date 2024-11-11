#pragma once
// #include <functional>
#include <string_view>

#include "IO.h"
#include "TLS.h"
#include "Servinfo.h"

#include <unistd.h> //close, read, write

constexpr int CLOSED = -1;

static void handle_error(const char* msg, bool exit_proc=false)
{
    perror(msg); 
    if(exit_proc) {exit(EXIT_FAILURE);}
};

static int closeFd(int fileDescriptor)
{   
    std::fprintf(stderr,"Close fd: %u\n",fileDescriptor);
    return close(fileDescriptor);
};

namespace COM
{
    class EndPoint : IO
    {
    private:
        std::string_view _ip;
        std::string_view _port;
        TLS _tls;
        int _fd = CLOSED; /* file descriptor */
        int connectTCP();
    public:
        EndPoint (std::string_view &ip, std::string_view &port, bool ssl);
        ~EndPoint ();
        bool connectIO ();
        bool closeIO ();
        int operator()() {return _fd;}
        int read (void* buffer, int count) override;
        int write (const void* buffer, int count) override;

    };

}