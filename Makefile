CC = gcc
CFLAGS = -m32 -shared -O2 -Wall
LDFLAGS = -Wl,--enable-stdcall-fixup -lgdi32 -luser32 -lkernel32 -lshell32

SRC = src/utf8_hook.c
D3D9_DEF = src/d3d9.def
VERSION_DEF = src/version.def

TARGET = d3d9.dll

all: $(TARGET)

d3d9: d3d9.dll
version: version.dll

d3d9.dll: $(SRC) $(D3D9_DEF)
	$(CC) $(CFLAGS) $(SRC) $(D3D9_DEF) -o $@ $(LDFLAGS)

version.dll: $(SRC) $(VERSION_DEF)
	$(CC) $(CFLAGS) $(SRC) $(VERSION_DEF) -o $@ $(LDFLAGS)

clean:
	rm -f d3d9.dll version.dll *.o

.PHONY: all clean d3d9 version
