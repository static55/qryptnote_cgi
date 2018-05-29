all: base64.o cgic.o qrypt.o
	gcc -std=c99 -o qrypt.cgi cgic.o qrypt.o base64.o `libgcrypt-config --libs`
	rm base64.o qrypt.o cgic.o

cgic.o:
	gcc -c cgic/cgic.c

qrypt.o:
	gcc -std=c99 -c qrypt.c -I./cgic `libgcrypt-config --cflags`

base64.o:
	gcc -c base64.c

clean:
	rm base64.o qrypt.o cgic.o qrypt.cgi
