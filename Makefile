CC = gcc
CFLAGS = -m32 -shared -O2 -Wall
LDFLAGS = -lgdi32 -luser32 -lkernel32 -lshell32

SRC = src/utf8_hook.c
DEF = src/version.def
TARGET = version.dll

all: $(TARGET)

$(TARGET): $(SRC) $(DEF)
	$(CC) $(CFLAGS) $(SRC) $(DEF) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
