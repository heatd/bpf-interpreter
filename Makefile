CXXFLAGS:=-Wall -Wextra -O2 -fsanitize=address -fsanitize=undefined

.PHONY: all clean

all: cbpf

OBJS:=cbpf.o

cbpf: $(OBJS)
	$(CXX) $(OBJS) $(CXXFLAGS) -o $@

clean:
	rm -f $(OBJS) cbpf
