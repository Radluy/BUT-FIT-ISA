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


//dns -s server [-p port] -f filter_file
int main(int argc, char *argv[])
{
    using namespace std;
    const char *const short_opts = "s:f:p:";

    string server;
    string filter_file;
    int port = 53;
    while (true)
    {
        const auto opt = getopt(argc, argv, short_opts);
        if (-1 == opt)
            break;

        switch (opt)
		{
		case 's':
            if (optarg == nullptr)
                break;
            server.assign(optarg);
            break;

        case 'p':
			port = stoi(optarg);
			break;

		case 'f':
            if (optarg == nullptr)
                break;
            filter_file.assign(optarg);
            break;
        
        default:
            cerr << "usage: dns -s server [-p port] -f filter_file";
            return -1;
        }
    }
    cout << server << "\n" << port << "\n" << filter_file << "\n";
}
