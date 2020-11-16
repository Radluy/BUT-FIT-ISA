
#start server
g++ dns.cpp -g -o dns > /dev/null 2>&1
echo "starting server..."
echo "dns server: 8.8.8.8"
echo "port: 6789"
echo "filterfile2.txt"
./dns -s 8.8.8.8 -f filterfile2.txt -p 6789 > /dev/null 2>&1 & 

#wis.fit.vutbr.cz A
expected=$(echo "status: NOERROR" | xargs)
output=$(dig @localhost -p 6789 wis.fit.vutbr.cz | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying wis.fit.vutbr.cz"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#docs.google.com A
expected=$(echo "status: NOERROR" | xargs)
output=$(dig @localhost -p 6789 A docs.google.com | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying docs.google.com"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#8.8.8.8 PTR
expected=$(echo "status: NOTIMP" | xargs)
output=$(dig @localhost -p 6789 PTR 8.8.8.8 | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying 8.8.8.8 PTR(not supported query type)"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#8.8.8.8 A
expected=$(echo "status: NXDOMAIN" | xargs)
output=$(dig @localhost -p 6789 A 8.8.8.8 | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying 8.8.8.8 A(wrong domain name)"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#zzz.cn A
expected=$(echo "status: REFUSED" | xargs)
output=$(dig @localhost -p 6789 A zzz.cn | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying zzz.cn(blacklisted)"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#sub.dom.zzz.cn A
expected=$(echo "status: REFUSED" | xargs)
output=$(dig @localhost -p 6789 sub.dom.zzz.cn | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying sub.dom.zzz.cn(subdomain of blacklisted)"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#kill server
echo "killing server..."
echo " "
trap "kill 0" EXIT

#start new server
echo "starting server..."
echo "dns server: dns.google.com"
echo "port: 5555"
echo "filterfile2.txt"
./dns -s dns.google.com -f filterfile2.txt -p 5555 > /dev/null 2>&1 & 

#cas.fit.vutbr.cz A
expected=$(echo "status: NOERROR" | xargs)
output=$(dig @localhost -p 5555 cas.fit.vutbr.cz | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying cas.fit.vutbr.cz"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#xelias18@fit.vutbr.cz MX
expected=$(echo "status: NOTIMP" | xargs)
output=$(dig @localhost -p 5555 mx xelias18@fit.vutbr.cz | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying xelias18@fit.vutbr.cz MX"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#kill server
echo "killing server..."
trap "kill 0" EXIT

#start new server
echo "starting server..."
echo "dns server: ::ffff:8.8.8.8"
echo "port: 9134"
echo "filterfile2.txt"
./dns -s ::ffff:8.8.8.8 -f filterfile2.txt -p 9134 > /dev/null 2>&1 & 

#seznam.cz A
expected=$(echo "status: NOERROR" | xargs)
output=$(dig @localhost -p 9134 seznam.cz | grep "status" | cut -d ',' -f 2 | xargs)
echo "...querying seznam.cz"
echo "expected: $expected"
echo "output:   $output"
if [ "$expected" = "$output" ]; then
    echo -e "\e[32m-->   TEST PASSED\e[0m"
else
    echo -e "\e[31m-->   TEST FAILED\e[0m"
fi

#kill server
echo "killing server..."
trap "kill 0" EXIT
