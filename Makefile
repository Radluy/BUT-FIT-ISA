CC=g++
BIN=dns
OPTIONS=

all:
	$(CC) dns.cpp -g -o $(BIN)
run: all
	./$(BIN) $(OPTIONS)
example: all
	./$(BIN) -s 8.8.8.8 -f filterfile2.txt -p 5353	
clean: 
	rm $(BIN)
test: all
	./tests.sh
