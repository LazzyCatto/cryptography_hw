SRCS := $(shell find ./src -name '*.cpp')
OBJS := $(SRCS:.cpp=.o)

ALL_SRCS := $(find . -name '*.cpp')
ALL_DEPS := $(ALL_SRCS:.cpp=.d)

CXX := g++
CXXFLAGS := -I. -std=c++20 -MMD -MP

test: test.out
	./test.out

test.out: $(OBJS) test.o
	$(CXX) $(OBJS) test.o -o test.out

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(ALL_SRCS:.cpp=.o) $(ALL_DEPS) $(shell find . -name '*.out')

ifneq ($(MAKECMDGOALS),clean)
-include $(ALL_DEPS)
endif

.PHONY: clean
