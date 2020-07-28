all: pack_test

pack_test: main.o
	g++ -o pack_test main.o -lpcap

main.o: main.cpp headers.h
	g++ -c -o main.o main.cpp

clean:
	rm -f main.o 
