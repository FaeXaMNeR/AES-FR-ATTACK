CXX = g++
CXXFLAGS = -std=c++17 -O0 -Wall -Wextra -march=native -Iinclude
LDFLAGS =
OPENSSL_LIBS = -lcrypto

SRCDIR = src
BINDIR = bin

all: $(BINDIR)/fr_attack $(BINDIR)/openssl_attack \
     $(BINDIR)/mitigation_attack $(BINDIR)/bench_aes \
     $(BINDIR)/openssl_software_attack $(BINDIR)/race_attack

$(BINDIR)/fr_attack: $(SRCDIR)/fr_attack.cpp $(SRCDIR)/aes_victim.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BINDIR)/openssl_attack: $(SRCDIR)/openssl_attack.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(OPENSSL_LIBS)

$(BINDIR)/mitigation_attack: $(SRCDIR)/mitigation_attack.cpp \
                             $(SRCDIR)/aes_victim.cpp \
                             $(SRCDIR)/aes_victim_cleansed.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BINDIR)/bench_aes: $(SRCDIR)/bench_aes.cpp \
                     $(SRCDIR)/aes_victim.cpp \
                     $(SRCDIR)/aes_victim_cleansed.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BINDIR)/openssl_software_attack: $(SRCDIR)/openssl_software_attack.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(OPENSSL_LIBS)

$(BINDIR)/race_attack: $(SRCDIR)/race_attack.cpp \
                       $(SRCDIR)/aes_victim.cpp \
                       $(SRCDIR)/aes_victim_cleansed.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ -lpthread

$(BINDIR):
	mkdir -p $@

clean:
	rm -rf $(BINDIR)

run: $(BINDIR)/fr_attack
	./$(BINDIR)/fr_attack

run-openssl: $(BINDIR)/openssl_attack
	./$(BINDIR)/openssl_attack

run-mitigation: $(BINDIR)/mitigation_attack
	./$(BINDIR)/mitigation_attack

run-bench: $(BINDIR)/bench_aes
	./$(BINDIR)/bench_aes

run-openssl-software: $(BINDIR)/openssl_software_attack
	./$(BINDIR)/openssl_software_attack

run-race: $(BINDIR)/race_attack
	./$(BINDIR)/race_attack

.PHONY: all clean run run-openssl run-mitigation run-bench run-openssl-software run-race