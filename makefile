SRCS := $(shell git ls-files '*.cpp')
HDRS := $(shell git ls-files '*.h')

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
