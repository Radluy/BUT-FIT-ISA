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