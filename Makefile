%.o: %.c
	gcc -Wall -g -c $?

all: parser

parser: cap_parser.o
	gcc -g -o parser cap_parser.c -lpcap

clean:
	rm *.o parser
