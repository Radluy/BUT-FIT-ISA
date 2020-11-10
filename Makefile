CC=g++
BIN=dns
OPTIONS=

all:
	$(CC) dns.cpp -g -o $(BIN) -lpcap
run: all
	sudo ./$(BIN) $(OPTIONS)
example: all
	sudo ./$(BIN) -s 8.8.8.8 -f filterfile -p 1234	
clean: 
	rm $(BIN)