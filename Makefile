%.o: %.c
	gcc -Wall -g -c $?

all: parser

parser: cap_parser.o util.o
	gcc -g -o parser cap_parser.o util.o -lpcap

clean:
	rm *.o parser
