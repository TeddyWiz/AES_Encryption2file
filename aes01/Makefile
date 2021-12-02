#.SUFFIXES:.c.o
CC=gcc
#CFLAGS = -g -O2 -Wall
TARGET = aes_test
OBJS = aes.o main.o
$(TARGET) : $(OBJS)
   $(CC) -o $(TARGET) $(OBJS)

aes.o : aes.c
   $(CC) -c -o $<

main.o : main.c
   $(CC) -c -o $?

clean : 
   rm *.o $(TARGET)