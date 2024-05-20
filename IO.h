#pragma once
 

namespace COM
{
    class IO
    {
        public:
        virtual int read(void* buffer, int count) = 0;
        virtual int write(const void* buffer, int count) = 0;
    };
}