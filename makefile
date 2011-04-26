# Time-stamp: <2004-07-27 08:44:56 pca>
# File: Makefile

CFLAGS+=-c -Wall -g

target=MArCd
MYSQL_INCL  = -I/usr/include/mysql
objects = main.o

all: $(objects)
	$(CXX) $(LDFLAGS) -o $(target) main.o -L/usr/lib/mysql -lmysqlclient -lz -lcrypt

%.o: %.cpp
	$(CXX) $(CFLAGS) main.cpp $(MYSQL_INCL)

clean:
	rm -f *.o *.exe $(target)
