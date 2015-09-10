CC=g++ 
LD=ld

#CFLAGS=-D__LINUX__ -DUSE_DANGEROUS_FUNCTIONS -D__PLUGIN__ -D__X64__
#CFLAGS=-m32 -fPIC -D__LINUX__ -DUSE_DANGEROUS_FUNCTIONS -D__PLUGIN__ -D__EA64__

CFLAGS=-m32 -fPIC -D__LINUX__ -DUSE_DANGEROUS_FUNCTIONS -D__PLUGIN__ 
LDFLAGS=-shared -m32

# TODO: add conditional compilation over -lida or -lida64 based on the X64
#LIBS= -lida64 -lpro -lc -lpthread -ldl
LIBS= -lida -lpro -lc -lpthread -ldl

LIBDIR=-L./ -L$(IDA_DIR) -L/usr/lib/i386-linux-gnu/
SRCDIR=./
HEXRAYS_SDK=$(IDA_DIR)/plugins/hexrays_sdk
SRC=$(SRCDIR)CodeXplorer.cpp \
	$(SRCDIR)GraphBuilder.cpp \
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

all: HexRaysCodeExplorer.plx

HexRaysCodeExplorer.plx: $(OBJS)
	#ln -f -s $(IDA_SDK)/lib/x64_linux_gcc_64/pro.a libpro.a
	ln -f -s $(IDA_SDK)/lib/x86_linux_gcc_32/pro.a libpro.a
	$(CC) $(LDFLAGS) $(LIBDIR) -o HexRaysCodeExplorer.plx $(OBJS) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) HexRaysCodeExplorer.plx

install:
	cp -f HexRaysCodeExplorer.plx $(IDA_DIR)/plugins
