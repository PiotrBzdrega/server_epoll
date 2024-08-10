#include <sys/types.h> // bind
#include <sys/socket.h> // connect, bind
#include <netdb.h> // getaddrinfo, getnameinfo
#include <arpa/inet.h> // inet_ntop
#include <unistd.h> // close
#include <string.h> // strerror
#include <getopt.h> // getopt_long
#include <sys/wait.h> //wait
#include <sys/epoll.h> //epoll
#include <sys/file.h>
#include <errno.h>
#include <signal.h> //signal
#include <sys/signalfd.h> //signalfd

#include <iostream>
#include <cstring>
#include <string>
#include <unordered_set> // std::unordered_set

#include "Servinfo.h"
// #include "EndPoint.h"

constexpr int MAX_READ = 2048;

/* signal detection variable */
volatile sig_atomic_t sig_received = 0;

void signal_handler(int)
{
    sig_received = 1;
};

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

auto reply = [](int n){return std::string("Received "+ std::to_string(n) + " bytes.");};

int main(int argc, char *argv[])
{
    bool with_tls = false;
    constexpr auto MAXEVENTS = 64;
    int ret;

#ifdef __linux__
    /* if file doesn't exist, permission level must be determined */
    int pid_file = open("/var/run/server.pid", O_CREAT | O_RDWR, 0666); //read and write permissions for the owner, group, and others
    ret = flock(pid_file, LOCK_EX | LOCK_NB);
    if(ret) {
        if(EWOULDBLOCK == errno)
        {
            std::cout<<"\033[0;91m another instance is running \033[0m\n";
            handle_error("flock",true);
        }
    }
#elif _WIN32

#endif

    /* hashmap for epoll list */
    std::unordered_set<int> fd_set;

    auto close_fd = [&fd_set](int fd = -1)
    {
        if (fd == -1)
        {
            /* close all fd and clear container*/
            for (auto i : fd_set)
            {
                close(i);
                std::printf("Close fd: %d\n",i);
            }
            fd_set.clear();
        
        }
        else
        {
            /* close only given fd*/
            if (auto iter = fd_set.find(fd); iter != fd_set.end())
            {
                close(*iter);
                std::printf("Close fd: %d",*iter);
                fd_set.erase(iter);
            }       
        }  
    };

    std::string interface;
    std::string porti;
    int option_index = 0;
    static struct option long_options[] = {
            {"ip",      required_argument, 0,  'i' },
            {"port",    required_argument, 0,  'p' },
            {"ssl",     no_argument,       0,   1  },
            {0,         0,                 0,   0  }
        };

    while ((ret = (getopt_long(argc,argv,"i:p:",long_options, &option_index))) != -1)
    {
        switch (ret)
        {
        case 0:
          /* If this option set a flag, do nothing else now. */
          if (long_options[option_index].flag != 0)
            break;
          printf ("option %s", long_options[option_index].name);
          if (optarg)
            printf (" with arg %s", optarg);
          printf ("\n");
          break;
        case 1:
            printf ("option %s\n", long_options[option_index].name);
            with_tls = true;
            break;
        case '?':
          printf ("Unknown argument\n");
          break;

        case 'i':
          printf ("option -i with value `%s'\n", optarg);
          break;

        case 'p':
          printf ("option -p with value `%s'\n", optarg);
          break;
        }
    }

    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
    {
        printf ("non-option ARGV-elements: ");
        while (optind < argc)
        {
            printf ("%s ", argv[optind++]);
        }

        putchar ('\n');
    }
    

    constexpr int c_port = 3490; /* check if not used "netstat -tulpn" */
    std::string port(std::to_string(c_port));

    struct addrinfo hints = {0}; 
    {
        hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_STREAM; /* TCP */
        hints.ai_flags = AI_PASSIVE;     /* Socket address is intended for `bind' */
        /* By using the AI_PASSIVE flag, I’m telling the program to bind to the IP of the host it’s running on. 
        If you want to bind to a specific local IP address, drop the AI_PASSIVE and put an IP address in for the first argument to getaddrinfo().
        in this case AI_PASSIVE flag is ignored */
    }


    
    Servinfo servinfo;
    /* Translate name of a service location and/or a service name to set of socket addresses*/
    ret = getaddrinfo( nullptr, //"172.22.64.1",  //"localhost", /* e.g. "www.example.com" or IP */
                            port.c_str(), /* e.g. "http" or port number  */
                            &hints, /* prepared socket address structure*/
                            &servinfo); /* pointer to sockaddr structure suitable for connecting, sending, binding to an IP/port pair*/

    if (ret) 
    {
        std::cout<<"EAI error: "<<gai_strerror(ret)<<"\n";
        handle_error("getaddrinfo",true);
    }
    
    int fd; /* server file descriptor */
    ret = -1; /* reset in case of empty list of servinfo */
    for(struct addrinfo *ptr = servinfo; ptr != nullptr;  ptr= ptr->ai_next)
    { 
        char host[256],service[256];
        ret = getnameinfo(ptr->ai_addr, ptr->ai_addrlen,
                    host,sizeof(host),
                    service,sizeof(service),0);

        if (ret) 
        {
            std::cout<<"EAI error: "<<gai_strerror(ret)<<"\n";
            handle_error("getnameinfo");
            continue;
        }
        

        /* IPv4 and IPv6 addresses from binary to text form*/
        char addr[INET6_ADDRSTRLEN]={0};
        switch (ptr->ai_family)
        {
        case AF_INET:
            inet_ntop(ptr->ai_family,&(reinterpret_cast<struct sockaddr_in *>(ptr->ai_addr)->sin_addr),addr,sizeof(addr));
            break;

        case AF_INET6:
            inet_ntop(ptr->ai_family,&reinterpret_cast<struct sockaddr_in6 *>(ptr->ai_addr)->sin6_addr,addr,sizeof(addr));
            break;
        }

        if (addr == nullptr) { handle_error("getnameinfo"); continue; }
        

        std::cout<< "\nIP: "<< addr <<
            "\nhost: "<<  host <<
            "\nport/service: "<< service <<
            "\ntransport layer: " << ((ptr->ai_socktype == SOCK_STREAM) ? "TCP" : (ptr->ai_socktype == SOCK_DGRAM) ? "UDP" : "OTHER")<<
            "\nprotocol: "<<ptr->ai_protocol<<
            "\n" ;


        fd = socket(ptr->ai_family,ptr->ai_socktype,ptr->ai_protocol);
        if (fd == -1) { handle_error("socket"); continue;}

/* modify the behavior of the socket */
        int on = 1;
#ifdef __linux__
        ret = setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&on,sizeof(on)); /* SO_REUSEADDR allows your server to bind to an address which is in a TIME_WAIT state */
#elif _WIN32
        ret = setsockopt(sock,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(char *)&on,sizeof(on)); /* The SO_EXCLUSIVEADDRUSE option prevents other sockets from being forcibly bound to the same address and port */
#endif
        if (ret == -1)
        {
            close(fd);
            handle_error("setsockopt");
            continue;
        }

        /* bind port to socket */
        ret = bind(fd, ptr->ai_addr, ptr->ai_addrlen);
        if (ret != 0)
        {
            close(fd);
            handle_error("bind");          
            continue;
        }

        /* get file descriptor flags */
        ret = fcntl(fd,F_GETFL,0);
        if(ret == -1)
        {
            close(fd);
            handle_error("fctl-get",false);          
            continue;
        }

        /* set as non-blocking if it is not set yet */
        auto flags = ret | O_NONBLOCK;
        ret = fcntl (fd, F_SETFL, flags);
        if(ret == -1)
        {
            close(fd);
            handle_error("fctl-set");
            continue;
        }
        /* leave loop with first succesfully created socket*/
        ret = 0; break;
    }

  //signal(SIGINT,signal_handler); change disposition of signal

    if (ret == 0)
    {
        ret = listen (fd, SOMAXCONN);
        if (ret == -1)
        {
            close(fd);
            handle_error("listen",true);      
        }

        std::cout<<"Server started\n";   

        //epoll interface
        auto fd_epoll = epoll_create1(0);
        if (ret == -1)
        {
            close(fd);
            handle_error("epoll_create1",true);      
        }

        /* setup event for listening socket*/
        struct epoll_event event;

        event.data.fd = fd;
        event.events = EPOLLIN | EPOLLET; /* edge-triggered read */

        /*  Add an entry to the interest list of the epoll file descriptor, fd_epoll */
        ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD ,fd, &event);
        if (ret == -1)
        {
            close(fd);
            handle_error("epoll_ctl",true);      
        }
        fd_set.insert(fd);

        /* BLOCK SIGNALS TO RECEIVE SIGNAL FROOM EPOLL */
        sigset_t mask;
        sigemptyset(&mask); /* initialize set w/o members */
        sigaddset(&mask, SIGTERM); /* append signal to set */
        sigaddset(&mask, SIGINT); /* Control-C */
	      sigaddset(&mask, SIGQUIT); /* Control-\ */
        sigaddset(&mask, SIGSTOP);
        sigaddset(&mask, SIGTSTP); /* Control-Z */
        ret = sigprocmask(SIG_BLOCK, &mask, 0); /* block signals from set */
        if(ret == -1)
        {
            close_fd();
            handle_error("sigprocmask",true); 
        }
	    int signal_fd = signalfd(-1, &mask, SFD_NONBLOCK); /* create file descriptor out of signal set */
        if(signal_fd == -1)
        {
            close_fd();
            handle_error("signalfd",true); 
        }

        /* clear before again usage */
        std::memset(&event, 0, sizeof(struct epoll_event));

        event.data.fd = signal_fd;
        event.events = EPOLLIN;
        ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, signal_fd, &event);
        if (ret == -1)    
        {
            close_fd();
            handle_error("epoll_ctl",true); 
        }
        fd_set.insert(signal_fd);

        struct epoll_event *events;
        /* clean Buffer where events are returned */
        events = (struct epoll_event*)  calloc (MAXEVENTS, sizeof event);

        while (1)
        {
            char buf[MAX_READ]={0};

            auto wait = epoll_wait(fd_epoll, events, MAXEVENTS, -1); //wait infinite time for events
            if (ret == -1)
            {
                close_fd();
                handle_error("epoll_wait",true);      
            }
            for (size_t i = 0; i < wait; i++)
            {
              /* error or hang up happend */
                if ((events[i].events & EPOLLERR) ||
                    (events[i].events & EPOLLHUP) ||
                    (!(events[i].events & EPOLLIN)))
                {
                    fprintf (stderr, "epoll error. events=%u\n", events[i].events);

                    int error = 0;
                    socklen_t errlen = sizeof(error);
                    if (getsockopt(events[i].data.fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen) == 0)
                    {
                        printf("error = %s\n", strerror(error));
                    }

	                close_fd(events[i].data.fd);
	                continue;
                }
                else
                if (signal_fd == events[i].data.fd)
                { 
                    while (1)
                    {
                        struct signalfd_siginfo fdsi;
                        ret = read(events[i].data.fd, &fdsi,sizeof(struct signalfd_siginfo)); 
                        if (ret == -1)
                        {
                            if (errno != EAGAIN)
                            {
                                handle_error("read");
                            }
                            break;
                        }
                        else
                        if (ret == sizeof(struct signalfd_siginfo))
                        {
                            std::cout << "Got signal"<<strsignal(fdsi.ssi_signo)<<"\n";
                            /* close all file description */
                            close_fd();
                            sleep(5);
                            exit(EXIT_FAILURE);
                        }
                        else
                        {
                            std::cout<<"[Error] Read from signal fd contains: "<< ret<<" bytes\n";
                            break;
                        }           
                    }
                } 
                else
                if (fd == events[i].data.fd)
                {
                    /* We have a notification on the listening socket, which
                    * means one or more incoming connections. */

                    while (1)
                    {
                        struct sockaddr in_addr;
                        socklen_t in_len;

                        in_len = sizeof in_addr;
                        int fd_in = accept(fd, &in_addr, &in_len);
                        if (fd_in == -1)
                        {
                            printf("errno=%d, EAGAIN=%d, EWOULDBLOCK=%d\n", errno, EAGAIN, EWOULDBLOCK);
                            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                            {
                                printf ("processed all incoming connections.\n");
                                break;
                            }
                            else
                            {
                                perror ("accept");
                                break; 
                            } 

                        }

                        /* IPv4 and IPv6 addresses from binary to text form*/
                        char addr[INET6_ADDRSTRLEN]={0};
                        switch (in_addr.sa_family)
                        {
                        case AF_INET:
                            inet_ntop(in_addr.sa_family,&(reinterpret_cast<struct sockaddr_in *>(in_addr.sa_data)->sin_addr),addr,sizeof(addr));
                            break;

                        case AF_INET6:
                            inet_ntop(in_addr.sa_family,&reinterpret_cast<struct sockaddr_in6 *>(in_addr.sa_data)->sin6_addr,addr,sizeof(addr));
                            break;
                        }

                        std::cout << "Incomming connection from "<<addr<<"\n";

                        /* Make the incoming socket non-blocking and add it to the list of fds to monitor. */
                        /* get file descriptor flags */
                        ret = fcntl(fd_in,F_GETFL,0);
                        if(ret == -1)
                        {
                            close_fd(fd_in);
                            handle_error("fctl-get");
                            break;        
                        }

                        /* set as non-blocking if it is not set yet */
                        auto flags = ret | O_NONBLOCK;
                        ret = fcntl (fd_in, F_SETFL, flags);
                        if(ret == -1)
                        {
                            close_fd(fd_in);
                            handle_error("fctl-set");
                            break;
                        }

                        event.data.fd = fd_in;
                        event.events = EPOLLIN | EPOLLET;
                        printf("set events %u, infd=%d\n", event.events,fd_in);
                        ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_in, &event);
                        if(ret == -1)
                        {
                            close_fd(fd_in);
                            handle_error("epoll_ctl");
                            break;
                        }
                        fd_set.insert(fd_in);

                        // auto msg= reply(all_reads);
                        // ret = write(events[i].data.fd,msg,sizeof msg);
                        // if (ret == -1)
                        // {
                          // handle_error("write");
                          // drop_connection = true;
                        // }   

                    }

                }
                else
                {
                    /* We have data on the fd waiting to be read. Read and
                     * display it. We must read whatever data is available
                     * completely, as we are running in edge-triggered mode
                     * and won't get a notification again for the same
                     * data. */
                    auto drop_connection = false;
                    int all_reads=0;
                    while (1)
                    {
                        /* If errno == EAGAIN, that means we have read all
                        * data. So go back to the main loop. */
                        ret = read(events[i].data.fd,buf,sizeof buf ); 
                        if (ret == -1)
                        {
                            if (errno != EAGAIN)
                            {
                                handle_error("read");
                                drop_connection = true;
                            }
                            else
                            {
                                auto msg= reply(all_reads);
                                ret = write(events[i].data.fd,msg.c_str(),msg.size());
                                if (ret == -1)
                                {
                                    if (errno != EAGAIN)
                                    {
                                        handle_error("write");
                                        drop_connection = true;
                                    } 
                                }                  
                                else
                                if (ret != msg.size())
                                {
                                    std::cout<<"different amnt of written bytes: "<<ret <<",in comparison to msg: "<<sizeof(msg)<<"\n";
                                }
                            }
                            break;
                        }
                        else
                        if (ret == 0)
                        {
                            /* End of file. The remote has closed the
                            * connection. */
                            drop_connection = true;
                            // break;
                        }
                        else
                        {
                            if (buf[ret-1]=='\n')
                            {
                                buf[ret-1]='\0';
                            }

                            std::cout<<"Received: "<<ret<<" bytes from fd: "<<events[i].data.fd<<"\n";
                            std::cout<<buf<<"\n";
                            all_reads+= ret;
                        }

                        if (drop_connection)
                        {
                          std::cout<<"Dropped connection on descriptor: "<< events[i].data.fd << "\n";
                          /* Closing the descriptor will make epoll remove it
                           * from the set of descriptors which are monitored. */
                          close_fd(events[i].data.fd);
                          break;
                        }
                }


            }

        }  
    }
  //TODO: use https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fullpath-wfullpath?view=msvc-170 or realpath in message exchange


    return 0;
}

}