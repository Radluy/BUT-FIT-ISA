CC=g++
BIN=dns
OPTIONS=

all:
	$(CC) dns.cpp -g -o $(BIN) -lpcap
run: all
	./$(BIN) $(OPTIONS)
example: all
	./$(BIN) -s 8.8.8.8 -f filterfile.txt -p 5353	
clean: 
	rm $(BIN)