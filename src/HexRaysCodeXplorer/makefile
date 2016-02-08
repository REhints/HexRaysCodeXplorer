CC=g++-5
LD=ld
IDA_DIR=/Applications/IDA\ Pro\ 6.8/IDA\ binaries

#CFLAGS=-D__LINUX__ -DUSE_DANGEROUS_FUNCTIONS -D__PLUGIN__ -D__X64__ -std=c++11 
#CFLAGS=-m32 -fPIC -D__LINUX__ -DUSE_DANGEROUS_FUNCTIONS -D__PLUGIN__ -D__EA64__ -std=c++11
CFLAGS=-m32 -fPIC -D__MAC__ -DUSE_DANGEROUS_FUNCTIONS -D__PLUGIN__ -std=c++11

LDFLAGS=-shared -m32

# TODO: add conditional compilation over -lida or -lida64 based on the X64
#LIBS= -lida64 -lpro -lc -lpthread -ldl
LIBS= -lida -lpro -lc -lpthread -ldl

LIBDIR=-L./ -L$(IDA_DIR)
SRCDIR=./
HEXRAYS_SDK=$(IDA_DIR)/plugins/hexrays_sdk
SRC=$(SRCDIR)CodeXplorer.cpp \
	$(SRCDIR)CtreeGraphBuilder.cpp \
	$(SRCDIR)ObjectExplorer.cpp \
	$(SRCDIR)TypeReconstructor.cpp \
	$(SRCDIR)CtreeExtractor.cpp \
	$(SRCDIR)TypeExtractor.cpp \
	$(SRCDIR)Utility.cpp \
	$(SRCDIR)ObjectFormatMSVC.cpp \
	$(SRCDIR)Debug.cpp
OBJS=$(subst .cpp,.o,$(SRC))
EXECUTABLE=HexRaysCodeXplorer
INCLUDES=-I$(IDA_SDK)/include -I$(HEXRAYS_SDK)/include

# only used on command line anyway
#DEFINE=__X64__ -D__LINUX__
#DEFINE=__EA64__ -D__LINUX__

all: HexRaysCodeXplorer.pmc

HexRaysCodeXplorer.pmc: $(OBJS)
	#ln -f -s $(IDA_SDK)/lib/x64_linux_gcc_64/pro.a libpro.a
	ln -f -s $(IDA_SDK)/lib/x86_mac_gcc_32/pro.a libpro.a
	$(CC) $(LDFLAGS) $(LIBDIR) -o HexRaysCodeXplorer.pmc $(OBJS) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) HexRaysCodeXplorer.pmc

install:
	cp -f HexRaysCodeXplorer.pmc $(IDA_DIR)/plugins
