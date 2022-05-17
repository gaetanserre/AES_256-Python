all:
	g++ src/shredder.cc -std=c++2a -o src/shredder

clean:
	rm -rf src/shredder