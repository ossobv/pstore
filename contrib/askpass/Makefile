CFLAGS = -Wall
EPREFIX = /usr/local

.PHONY: all clean install uninstall binaries

all: binaries

clean:
	$(RM) ssh_echopass ssh_echopass.o ssh_askpass.so

install: binaries
	install -d $(EPREFIX)/bin
	install ssh_echopass $(EPREFIX)/bin
	install -d $(EPREFIX)/lib
	install ssh_askpass.so $(EPREFIX)/lib
	ldconfig

uninstall:
	$(RM) $(EPREFIX)/bin/ssh_echopass.so 
	$(RM) $(EPREFIX)/lib/ssh_askpass.so
	
binaries: ssh_askpass.so ssh_echopass 

ssh_echopass: ssh_echopass.o

ssh_askpass.so: ssh_askpass.c
	$(CC) $(CFLAGS) -fPIC -shared -o ssh_askpass.so ssh_askpass.c -ldl

