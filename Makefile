CC ?= gcc
CFLAGS = -m32 -shared -O2 -Wall -Wextra -Wno-cast-function-type -Wno-unused-parameter
LDFLAGS = -static-libgcc -Wl,--enable-stdcall-fixup -lgdi32 -luser32 -lkernel32 -lshell32

SRC = src/utf8_hook.c
D3D9_DEF = src/d3d9.def
VERSION_DEF = src/version.def

# Detect RM
ifeq ($(OS),Windows_NT)
  RM ?= cmd /c "if exist d3d9.dll del /f /q d3d9.dll & if exist version.dll del /f /q version.dll & if exist test_exp.dll del /f /q test_exp.dll & if exist *.o del /f /q *.o & if exist *.exe del /f /q *.exe"
else
  RM ?= rm -f
endif

all: d3d9.dll

d3d9: d3d9.dll
version: version.dll

d3d9.dll: $(SRC) $(D3D9_DEF)
	$(CC) $(CFLAGS) $(SRC) $(D3D9_DEF) -o $@ $(LDFLAGS)

version.dll: $(SRC) $(VERSION_DEF)
	$(CC) $(CFLAGS) $(SRC) $(VERSION_DEF) -o $@ $(LDFLAGS)

clean:
	$(RM)

.PHONY: all clean d3d9 version
