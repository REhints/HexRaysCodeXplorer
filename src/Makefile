CC=g++ -m32
LD=ld
CFLAGS=-D__LINUX__ -DUSE_DANGEROUS_FUNCTIONS -D__PLUGIN__
LDFLAGS=-shared

HEXRAYS_SDK=$(IDA_DIR)/plugins/hexrays_sdk

INCLUDES=-I$(IDA_SDK)/include -I$(HEXRAYS_SDK)/include
LIBDIR=-L./ -L$(IDA_DIR)
LIBS= -lida -lpro -lc -lpthread -ldl

SRCDIR=HexRaysCodeXplorer/
SRC=$(SRCDIR)CodeXplorer.cpp \
	$(SRCDIR)GraphBuilder.cpp \
	$(SRCDIR)IdaGraphBuilder.cpp \
	$(SRCDIR)ObjectExplorer.cpp \
	$(SRCDIR)ObjectType.cpp
OBJS=$(subst .cpp,.o,$(SRC))

all: HexRaysCodeExplorer.plx

HexRaysCodeExplorer.plx: $(OBJS)
	ln -f -s $(IDA_SDK)/lib/x86_linux_gcc_32/pro.a libpro.a
	$(CC) $(LDFLAGS) $(LIBDIR) -o HexRaysCodeExplorer.plx $(OBJS) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS)
