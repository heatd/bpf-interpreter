CXXFLAGS:=-Wall -Wextra -O2 -fsanitize=address -fsanitize=undefined -g

.PHONY: all clean

all: cbpf

OBJS:=cbpf.o

cbpf: $(OBJS)
	$(CXX) $(OBJS) $(CXXFLAGS) -o $@

JITOBJS:=x86jit.o

jit: $(JITOBJS)
	$(CXX) $(JITOBJS) $(CXXFLAGS) -o $@

clean:
	rm -f $(OBJS) cbpf
