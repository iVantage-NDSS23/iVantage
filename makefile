all : isav rvping targetgen spooftest
.PHONY : clean

targetgen: targetgen.o src/common.o
	clang -o targetgen targetgen.o src/common.o -g

targetgen.o: targetgen.c
	clang -c targetgen.c -o targetgen.o

rvping: rvping.o src/probe.o src/sniffer.o src/common.o
	clang -o rvping rvping.o src/probe.o src/sniffer.o src/common.o -lpcap -pthread -g

rvping.o: rvping.c src/common.h
	clang -c rvping.c -o rvping.o 

isav: isav.o src/common.o src/probe.o src/sniffer.o
	clang -o isav isav.o src/common.o src/probe.o src/sniffer.o  -lpcap -pthread -g

isav.o: isav.c 
	clang -c isav.c -o isav.o 

spooftest: spooftest.o src/common.o src/probe.o src/sniffer.o
	clang -o spooftest spooftest.o src/common.o src/probe.o src/sniffer.o  -lpcap -pthread -g

spooftest.o: spooftest.c 
	clang -c spooftest.c -o spooftest.o 

src/probe.o: src/probe.c src/probe.h src/common.h
	clang -c src/probe.c -o src/probe.o

src/sniffer.o: src/sniffer.c src/sniffer.h src/common.h
	clang -c src/sniffer.c -o src/sniffer.o 

src/common.o: src/common.c src/common.h
	clang -c src/common.c -o src/common.o

clean:
	rm -rf *.o src/*.o isav targetgen rvping spooftest