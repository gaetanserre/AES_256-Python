#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <unistd.h>
#include <random>
#include <fcntl.h>
using namespace std;

random_device dev;
mt19937 rng(dev());
unsigned int get_random_index(const unsigned int &max_idx) {
  uniform_int_distribution<mt19937::result_type> dist(0, max_idx);
  return dist(rng);
}

unsigned int get_size(const char* filename) {
  filesystem::path p(filename);
  return filesystem::file_size(p);
}

void shred_file(const char* filename, auto f) {
  unsigned int filesize = get_size(filename);
  for(int i = 0; i<filesize; i++) {
    int file = open(filename, O_WRONLY);
    char byte = f();    
    pwrite(file, (void*) &byte, 1, i);
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    throw runtime_error("No filename provided.");
    return -1;
  }

  char possible_bytes[256];
  for(int i = 0; i<=0xFF; i++) {
    possible_bytes[i] = (char) i;
  }

/*   // Write 0s
  auto f1 = [&](){return possible_bytes[0];};
  shred_file(argv[1], f1);

  // Write 1s
  auto f2 = [&](){return possible_bytes[255];};
  shred_file(argv[1], f2); */

  // Write random bytes
  auto f3 = [&](){return possible_bytes[get_random_index(256)];};
  shred_file(argv[1], f3);
  
  return 0;
}