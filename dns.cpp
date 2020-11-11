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
#include <pcap/pcap.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define BUFFER_SIZE 1024
#define DEFAULT_PORT 53
#define DNS_HEADER_SIZE 12

struct DNS_HEADER
{
    unsigned short id ; // identification number
 
    unsigned char qr :1; // query/response flag
    unsigned char opcode :4; // purpose of message

    unsigned char aa :1; // authoritive answer
    unsigned char tc :1; // truncated message
    unsigned char rd :1; // recursion desired
    unsigned char ra :1; // recursion available
    unsigned char z :1; // its z! reserved

    unsigned char rcode :4; // response code
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};


//global flag
bool verbose = false;
/*forwards original query to specified dns server and sends response to client
*
*
*return length of response from resolver on success, -1 on error
*/ 
int forward_query(string dns_server, char buffer[BUFFER_SIZE], int message_size,struct sockaddr_in* client_address, int socket_file_descriptor)
{
    //dns_server = dns_server.substr(1);  //vscode debug only
    bool domain = false;
    struct sockaddr_in server_address, local_address;
    struct in_addr pton_res;
    struct addrinfo *result;
    socklen_t len;
    if (inet_pton(AF_INET, dns_server.c_str(), &pton_res) != 1) //try ipv4
    {
        
        if (inet_pton(AF_INET6, dns_server.c_str(), &pton_res) != 1)  //try ipv6
        {
            //linux man page of getaddrinfo
            struct addrinfo hints;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(nullptr, dns_server.c_str(), &hints, &result) != 0) //try domain name
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

    server_address.sin_addr = pton_res;
    server_address.sin_port = htons(DEFAULT_PORT);
    int forward_socket_fd, send_res;
    if ((forward_socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        cerr << "Creating socket file descriptor failed.\n" << strerror(errno) << "\n";
        return -1;
    }
    len = sizeof(server_address);
    //forward query to DNS server
    if (!domain)
    {
        send_res = sendto(forward_socket_fd, (const char *)buffer, message_size, 0, (const struct sockaddr *)&server_address, len);
    }
    else
    {
        send_res = sendto(forward_socket_fd, (const char *)buffer, message_size, 0, (const struct sockaddr *)&result->ai_addr, sizeof(result->ai_addr));
    }
    if (send_res == -1)
        cerr << "Forwarding failed.\n";
    
    //recieve response
    len = sizeof(local_address);
    if (getsockname(forward_socket_fd, (struct sockaddr *)&local_address, &len) == -1)
        cerr << "Getting local address failed.\n";

    //cout << "WAITING FOR RESPONSE\n";
    int message_length = recvfrom(forward_socket_fd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&local_address, &len);
    //cout << "MESSAGE RECIEVED\n"; //debug
    buffer[message_length] = '\0';

    //cout << "RESPONSE SENT TO CLIENT\n";
    return message_length;
}

/*
main function
...
foo bar
//dns -s server [-p port] -f filter_file
*/
int main(int argc, char *argv[])
{
    string server;
    string filter_file;
    char buffer[BUFFER_SIZE];
    int port = DEFAULT_PORT;
    while (true)
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
            cout << "usage: dns -s server [-p port] -f filter_file\n"
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
    //Create file descriptor for socket
    int socket_file_descriptor, new_socket;
    if ((socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        cerr << "Creating socket file descriptor failed.\n" << strerror(errno) << "\n";
        return -1;
    }

    //Set optional settings for socket: address reusability etc. 
    //if (setsockopt(socket_file_descriptor, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, nullptr, nullptr))

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
        //Listen for query
        ssize_t message_size = recvfrom(socket_file_descriptor, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_address, &len_c_adrress);
        buffer[message_size] = '\0';
        //sendto(socket_file_descriptor, buffer, message_size, 0, (struct sockaddr *)&client_address, len_c_adrress);    //DEBUG
        //Get requested domain name and query type from packet
        char *ptr = buffer;
        ptr += DNS_HEADER_SIZE; //always 12 bytes
        string req_domain;
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
        ptr += 1;
        short query_type = (((short)*ptr) << 8) | *(ptr+1); //cast 2 bytes to short 

        //forward query to specified dns resolver and send answer to client
        int rc = forward_query(server, buffer, message_size, &client_address, socket_file_descriptor);  
        if (rc == -1)
        {
            cerr << "Forwarding query failed.\n";
            continue;
        }
        int send_res = sendto(socket_file_descriptor, buffer, rc, 0, (struct sockaddr *)&client_address, len_c_adrress);
        if (send_res == -1)
        {
            cerr << "Forwarding failed.\n";
            continue;
        }

    }
    //https://www.geeksforgeeks.org/socket-programming-cc/
}
