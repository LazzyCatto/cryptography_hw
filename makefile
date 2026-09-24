MAIN_SRCS := $(shell git ls-files '*.cpp')
MAIN_HDRS := $(shell git ls-files '*.h')

CIPHER_SRCS := $(shell git ls-files --others --exclude-standard crypto/cipher | grep '\.cpp$$' || true)
CIPHER_HDRS := $(shell git ls-files --others --exclude-standard crypto/cipher | grep '\.h$$' || true)

HOST_KEY_SRCS := $(shell git ls-files --others --exclude-standard crypto/host_key | grep '\.cpp$$' || true)
HOST_KEY_HDRS := $(shell git ls-files --others --exclude-standard crypto/host_key | grep '\.h$$' || true)

KEX_SRCS := $(shell git ls-files --others --exclude-standard crypto/kex | grep '\.cpp$$' || true)
KEX_HDRS := $(shell git ls-files --others --exclude-standard crypto/kex | grep '\.h$$' || true)

MAC_SRCS := $(shell git ls-files --others --exclude-standard crypto/mac | grep '\.cpp$$' || true)
MAC_HDRS := $(shell git ls-files --others --exclude-standard crypto/mac | grep '\.h$$' || true)

SRCS = $(CIPHER_SRCS) $(HOST_KEY_SRCS) $(KEX_SRCS) $(MAC_SRCS)
HDRS = $(CIPHER_HDRS) $(HOST_KEY_HDRS) $(KEX_HDRS) $(MAC_HDRS)

OBJS := $(SRCS:.cpp=.o)

CXX := g++
CXXFLAGS := -I. -std=c++20

test: test.out
	./test.out

test.out: $(OBJS) test.o
	$(CXX) $(CXXFLAGS) $(OBJS) test.o -o test.out

%.o: %.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
