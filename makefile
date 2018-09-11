CC=gcc
CFLAGS=-Wall
NAME=gbdis

all: main.o ; $(CC) $(CFLAGS) $^ -o $(NAME)

main.o: main.c ; $(CC) $(CFLAGS) -c $^ 

.PHONY: clean

clean: ; rm $(NAME) *.o
