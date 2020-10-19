/*************************************
 *      Author: Radoslav Elias       *
 *************************************/

#include <iostream>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/udp.h>
#define BUFFER_SIZE 1024

using namespace std;

//dns -s server [-p port] -f filter_file
int main(int argc, char *argv[])
{
    string server;
    string filter_file;
    char buffer[BUFFER_SIZE];
    int port = 53;
    while (true)
    {
        const auto opt = getopt(argc, argv, "s:f:p:");

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
        
        default:
            cerr << "usage: dns -s server [-p port] -f filter_file\n";
            return -1;
        }
    }
    if (server.empty() or filter_file.empty())
    {
        cerr << "Option -s or -f is missing\n";
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

    //Listen for query
    ssize_t message_size = recvfrom(socket_file_descriptor, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_address, &len_c_adrress);
    
    buffer[message_size] = '\0';
    printf("%s", buffer);
    //https://www.geeksforgeeks.org/socket-programming-cc/
}
