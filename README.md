# Filtering DNS resolver

DNS resolver filtering queries by blacklist files. 
DNS type A queries over UDP are supported.

## Usage: 
dns -s server [-p port] -f filter_file [-v]   
    -s: ipv4/ipv6 adress or DNS server domain name where the query will be forwarded.  
    -p: TCP port number of the resolver. If not specified, the default port number is 53. 
    -f: file name for the blacklist. If the specified file doesn't exist, no filter is applied and all queries are forwarded. 
    -v: verbosity flag, prints info about current operations.  

## Usage example: 
    ./dns -s 8.8.8.8 -f filterfile2.txt -p 1234
or  
    make example

#
