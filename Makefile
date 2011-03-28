
CC = g++
CFLAGS = -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
        LIBS= -lssl -lcrypto
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
        LIBS= -lssl
else
	OSLIB=
	OSINC= 
	OSDEF=-DLINUX
        LIBS= -lssl -lcrypto
endif
endif

all:  http-server-$(EXEC_SUFFIX)

http-server-$(EXEC_SUFFIX): http-server-$(EXEC_SUFFIX).o smartalloc.o 
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ $^ $(LIBS)

http-server-$(EXEC_SUFFIX).o: http-server.cpp
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -c http-server.cpp -o http-server-$(EXEC_SUFFIX).o

smartalloc.o:   smartalloc.c smartalloc.h http-server-$(EXEC_SUFFIX).o
	gcc -Wall -Werror -g -c -o $@ $<



handin: README
	handin bellardo p4 README smartalloc.c smartalloc.h http-server.cpp Makefile

clean:
	rm -rf http-server-* http-server-*.dSYM
