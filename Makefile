CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -DDEBUG
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
TARGET = pe_parser.exe

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)