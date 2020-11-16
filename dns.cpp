/*************************************
 *      Author: Radoslav Elias       *
 *************************************/

using namespace std;
#include <iostream>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#define BUFFER_SIZE 1024
#define DEFAULT_PORT 53
#define DNS_HEADER_SIZE 12

//global flag
bool verbose = false;

/*
checks if domain is in blacklist
@param req_domain string containing domain name queried by client
@param filter_file name of file containing blacklisted domain names
returns true if requested domain is blacklisted, false otherwise
*/
bool filter(string req_domain, string filter_file)
{
    if (verbose)
            cout << "comparing domain to blacklist...\n";
    ifstream in(filter_file);
    string line;
    while (getline(in, line))
    {
        if (line.size() == 0 || line[0] == '#')
            continue;   //skip empty lines and comments
        
        if (req_domain.find(line) != string::npos)
            return true;
    }
    in.close();
    return false;
}

/*
forwards original query to specified dns resolver
@param dns_server name of filter file specified in arg -f
@param buffer buffer containing query from client
@param message_size length of message in buffer
@param client_address ip address struct of client 
return length of response from resolver on success, -1 on error
*/ 
int forward_query(string dns_server, char buffer[BUFFER_SIZE], int message_size,struct sockaddr_in* client_address)
{
    bool domain = false;
    struct sockaddr_in server_address, local_address;
    struct in_addr pton_res;
    struct addrinfo *result;
    struct sockaddr *sock_address;
    struct sockaddr_in6 ipv6_serv_address;
    socklen_t len;
    int dom_sockfd, forward_socket_fd, send_res, message_length;
    if (verbose)
            cout << "creating socket for dns resolver...\n";
    if (inet_pton(AF_INET, dns_server.c_str(), &server_address.sin_addr) != 1) //try ipv4
    {
        
        if (inet_pton(AF_INET6, dns_server.c_str(), &ipv6_serv_address.sin6_addr) != 1)  //try ipv6
        {
            //linux man page of getaddrinfo
            struct addrinfo hints;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_PASSIVE;    
            hints.ai_protocol = 0;          
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;
            char port[2];
            sprintf(port, "%d", DEFAULT_PORT);
            if (getaddrinfo(dns_server.c_str(), port, &hints, &result) != 0) //try domain name
            {
                cerr << "Incorrect IP address or domain name of DNS server specified.\n";
                return -1;
            }
            else
            {
                domain = true;
            }
        }
        server_address.sin_family = AF_INET6;
    }
    else
    {
        server_address.sin_family = AF_INET;
    }

    if (verbose)
            cout << "forwarding query to dns resolver...\n";
    //prepare variables for forwarding and send
    if (domain)
    {   //web.cecs.pdx.edu 
        do
        {   //try each address from addrinfo result
            forward_socket_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
            if (forward_socket_fd >= 0)
            break; //stop at success
        }
        while ((result = result->ai_next) != NULL);
        sock_address = (sockaddr*)malloc(result->ai_addrlen);   //allocate space for resolver address
        memcpy(sock_address, result->ai_addr, result->ai_addrlen);
        len = result->ai_addrlen;
        send_res = sendto(forward_socket_fd, (const char *)buffer, message_size, 0, sock_address, len);
        free(sock_address);
    }
    else    //server address is in ipv4/ipv6 form
    {
        server_address.sin_port = htons(DEFAULT_PORT);
        if ((forward_socket_fd = socket(server_address.sin_family, SOCK_DGRAM, 0)) < 0)
        {
            cerr << "Creating socket file descriptor failed.\n" << strerror(errno) << "\n";
            return -1;
        }
        if (server_address.sin_family == AF_INET)
        {   //send to ipv4 address
            len = sizeof(server_address);
            send_res = sendto(forward_socket_fd, (const char *)buffer, message_size, 0, (const struct sockaddr *)&server_address, len);
        }
        else
        {   //send to ipv6 address
            len = sizeof(sockaddr_in6);
            ipv6_serv_address.sin6_family = AF_INET6;
            ipv6_serv_address.sin6_port = htons(DEFAULT_PORT);
            send_res = sendto(forward_socket_fd, (const char *)buffer, message_size, 0, (const struct sockaddr *)&ipv6_serv_address, len);
        }
        }

    if (send_res == -1)
    {
        cerr << "Forwarding failed.\n";
        return -1;
    }
    //recieve response
    len = sizeof(local_address);
    if (getsockname(forward_socket_fd, (struct sockaddr *)&local_address, &len) == -1)
    {
        cerr << "Getting local address failed.\n";
        return -1;
    }

    if (verbose)
            cout << "waiting for response from dns resolver...\n";
    message_length = recvfrom(forward_socket_fd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&local_address, &len);
    if (verbose)
            cout << "response from resolver recieved...\n";
    buffer[message_length] = '\0';
    if (close(forward_socket_fd) != 0)
    {
        cerr << "Closing socket failed.\n";
        return -1;
    }
    return message_length;
}

/*
Get requested domain name and query type from packet
Check DNS header flags
*/
string parse_buffer(char *buffer, short *query_type)
{
    //Get requested domain name and query type from packet
    char *ptr = buffer;
    string req_domain;
    ptr += DNS_HEADER_SIZE; //always 12 bytes
    while (*ptr != '\000')  //example bytes in packet: \003www\003wis\003fit\005vutbr\002cz
    {
        int tmp = (int)*ptr;    //get length of next part
        ptr += 1;
        for (int i = 0; i < tmp; i++)
        {
            req_domain.append(1, ptr[i]);   //append byte by byte
        }
        if (ptr[tmp] != '\000')    
            req_domain.append(1, '.');   //add delimeter 
        ptr += tmp;
    }
    //Check recursion desire
    char recursion_desired = buffer[2] & 1; //00000001-> RD flag
    if (recursion_desired == '\001')
        buffer[3] |= 128; //set RA flag

    //Check if query type is the only supported "A" type
    if (verbose)
        cout << "checking query type flag...\n";
    ptr += 1;
    *query_type = (((short)*ptr) << 8) | *(ptr+1); //cast 2 bytes to short 
    if (*query_type != 1)
    {
        buffer[2] |= 128; //10000000-> QR(1) == response
        buffer[3] = buffer[3] & 240; //11110000-> clear RCODE
        buffer[3] = buffer[3] | 4; //00001000 RCODE(4) == not implemented
        if (verbose)
            cout << "sending NOT IMPLEMENTED response to client...\n";
    }
    return req_domain;
}

/*
set flags to refused query for blacklisted domain
*/
void set_refused(char * buffer)
{
    if (verbose)
        cout << "sending REFUSED response to client...\n";
    buffer[2] |= 128; //10000000-> QR(1) == response
    buffer[3] = buffer[3] & 240; //11110000-> clear RCODE
    buffer[3] = buffer[3] | 5; //00000101 RCODE(5) == refused
}
/*
usage: dns -s server [-p port] -f filter_file [-v]
*/
int main(int argc, char *argv[])
{
    string server;
    string filter_file;
    char buffer[BUFFER_SIZE];
    int port = DEFAULT_PORT;
    while (true)    //parse arguments
    {
        const auto opt = getopt(argc, argv, "s:f:p:hv");

        if (-1 == opt)
            break;

        switch (opt)
		{
		case 's':
            if (optarg == nullptr)
            {
                cerr << "DNS server not specified.\n";
                return -1;
            }
            server.assign(optarg);
            break;

        case 'p':
			port = stoi(optarg);
			break;

		case 'f':
            if (optarg == nullptr)
            {
                cerr << "Filter file not specified.\n";
                return -1;
            }
            filter_file.assign(optarg);
            break;
        
        case 'v':
            verbose = true;
            break;

        case 'h':
            cout << "usage: dns -s server [-p port] -f filter_file [-v]\n"
                    "[-s] IP address or domain name of DNS server the query will be forwarded to.\n"
                    "[-p] Port on which the program will listen for queries. Default port is 53 if options isn't specified.\n"
                    "[-f] Name of filter file containing blacklisted domains.\n"
                    "[-v] Program will run in verbose mode and log debugging information.\n"
                    "[-h] This help message will be printed.\n";
            return 0;

        default:
            cerr << "usage: dns -s server [-p port] -f filter_file\n";
            return -1;
        }
    }
    if (server.empty() or filter_file.empty())
    {
        cerr << "Option -s or -f is missing\n" << "usage: dns -s server [-p port] -f filter_file\n";
        return -1;
    }

    //check for existance of filterfile
    ifstream test(filter_file);
    if (!test.good())
        cerr << "Specified filter file does not exist. Filtering will have no effect.\n";
    test.close();

    //Create file descriptor for socket
    if (verbose)
        cout << "Creating socket file descriptor...\n";
    int socket_file_descriptor;
    if ((socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        cerr << "Creating socket file descriptor failed.\n" << strerror(errno) << "\n";
        return -1;
    }

    //Set optional settings for socket: address reusability etc. 
    /*int reuse = 1;
    if (setsockopt(socket_file_descriptor, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse, sizeof(reuse))< 0)
    {
        cerr << "Setting optional socket options failed.\n";
        return -1;
    }*/

    //Create server address
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(port);

    //Bind address to socket
    if ( bind(socket_file_descriptor, (struct sockaddr *)&address, sizeof(address)) <0)
    {
        cerr << "Binding address to socket failed.\n" << strerror(errno) << "\n";
        return -1;
    }

    //Client address for response message
    struct sockaddr_in client_address;
    socklen_t len_c_adrress = sizeof(client_address);

    while (true)
    {
        try
        {
            //Listen for query
            if (verbose)
                cout << "listening for query...\n";
            ssize_t message_size = recvfrom(socket_file_descriptor, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_address, &len_c_adrress);
            if (verbose)
                cout << "query recieved...\nparsing...\n";
            buffer[message_size] = '\0';
            short query_type;
            string req_domain = parse_buffer(buffer, &query_type);  //parse domain name and flags
            if (query_type != 1)
            {   //send NOTIMP
                int send_res = sendto(socket_file_descriptor, buffer, message_size, 0, (struct sockaddr *)&client_address, len_c_adrress);
                if (send_res == -1)
                {
                    cerr << "Forwarding failed.\n";
                    continue;
                }
                continue;
            }

            //search for requested domain in blacklist
            bool blacklisted = filter(req_domain, filter_file);
            if (blacklisted)
            {
                set_refused(buffer);
                int send_res = sendto(socket_file_descriptor, buffer, message_size, 0, (struct sockaddr *)&client_address, len_c_adrress);
                if (send_res == -1)
                {
                    cerr << "Forwarding failed.\n";
                    continue;
                }
                continue;
            }

            //forward query to specified dns resolver and send answer to client
            int rc = forward_query(server, buffer, message_size, &client_address);  
            if (rc == -1)
            {
                cerr << "Forwarding query failed.\n";
                continue;
            }
            if (verbose)
                cout << "sending response to client...\n";
            int send_res = sendto(socket_file_descriptor, buffer, rc, 0, (struct sockaddr *)&client_address, len_c_adrress);
            if (send_res == -1)
            {
                cerr << "Forwarding failed.\n";
                continue;
            }
        }
        catch(const exception& e)
        {
            close(socket_file_descriptor);
        }
        
    }
    //https://www.geeksforgeeks.org/socket-programming-cc/
}
