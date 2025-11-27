# HexRaysCodeXplorer Makefile for IDA SDK 9.2
# Supports Windows, Linux, and macOS

# Detect IDA SDK path
ifndef IDASDK
IDASDK = /Users/am/Desktop/idasdk92
endif

# Plugin name
PLUGIN_NAME = HexRaysCodeXplorer

# Source files
SRCDIR = HexRaysCodeXplorer
SOURCES = $(SRCDIR)/CodeXplorer.cpp \
          $(SRCDIR)/CtreeGraphBuilder.cpp \
          $(SRCDIR)/CtreeExtractor.cpp \
          $(SRCDIR)/Debug.cpp \
          $(SRCDIR)/GCCObjectFormatParser.cpp \
          $(SRCDIR)/GCCTypeInfo.cpp \
          $(SRCDIR)/GCCVtableInfo.cpp \
          $(SRCDIR)/IObjectFormatParser.cpp \
          $(SRCDIR)/MicrocodeExtractor.cpp \
          $(SRCDIR)/MSVCObjectFormatParser.cpp \
          $(SRCDIR)/ObjectExplorer.cpp \
          $(SRCDIR)/reconstructed_place_t.cpp \
          $(SRCDIR)/ReconstructableType.cpp \
          $(SRCDIR)/TypeExtractor.cpp \
          $(SRCDIR)/TypeReconstructor.cpp \
          $(SRCDIR)/Utility.cpp \
          $(SRCDIR)/Compat.cpp \
          $(SRCDIR)/ItaniumABI.cpp \
          $(SRCDIR)/MSVCRTTIEnhanced.cpp \
          $(SRCDIR)/ClangVTableParser.cpp \
          $(SRCDIR)/ImprovedObjectExplorer.cpp \
          $(SRCDIR)/ModernObjectExplorer.cpp

# Detect OS
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Common compiler flags
CXXFLAGS = -std=c++17 -D__PLUGIN__ -D__EA64__ -DIDA_SDK_VERSION=920
CXXFLAGS += -I$(IDASDK)/include -I$(SRCDIR)
CXXFLAGS += -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter

# OS-specific settings
ifeq ($(UNAME_S),Darwin)
    # macOS
    CXX = clang++
    CXXFLAGS += -D__MAC__
    LDFLAGS = -dynamiclib -undefined dynamic_lookup
    
    ifeq ($(UNAME_M),arm64)
        # Apple Silicon
        PLATFORM = arm64_mac_clang_64
        CXXFLAGS += -arch arm64
    else
        # Intel Mac
        PLATFORM = x64_mac_clang_64
        CXXFLAGS += -arch x86_64
    endif
    
    PLUGIN_EXT = .dylib
    LIBDIR = $(IDASDK)/lib/$(PLATFORM)
    LDFLAGS += -L$(LIBDIR) -lida

else ifeq ($(UNAME_S),Linux)
    # Linux
    CXX = g++
    CXXFLAGS += -D__LINUX__ -fPIC
    LDFLAGS = -shared
    
    ifeq ($(UNAME_M),x86_64)
        PLATFORM = x64_linux_gcc_64
    else
        PLATFORM = x86_linux_gcc_32
    endif
    
    PLUGIN_EXT = .so
    LIBDIR = $(IDASDK)/lib/$(PLATFORM)
    LDFLAGS += -L$(LIBDIR) -lida
    
else
    # Windows (MinGW or MSVC)
    ifdef MSVC
        # MSVC
        CXX = cl
        CXXFLAGS = /std:c++17 /D__NT__ /D__PLUGIN__ /D__EA64__ /DIDA_SDK_VERSION=920
        CXXFLAGS += /I$(IDASDK)/include /I$(SRCDIR)
        CXXFLAGS += /W3 /wd4996 /wd4800 /wd4267
        
        PLATFORM = x64_win_vc_64
        PLUGIN_EXT = .dll
        LIBDIR = $(IDASDK)/lib/$(PLATFORM)
        LDFLAGS = /DLL /LIBPATH:$(LIBDIR) ida.lib
        
        # Object file extension
        OBJ_EXT = .obj
    else
        # MinGW
        CXX = g++
        CXXFLAGS += -D__NT__ -D_WIN32_WINNT=0x0601
        LDFLAGS = -shared -Wl,--dll
        
        PLATFORM = x64_win_gcc_64
        PLUGIN_EXT = .dll
        LIBDIR = $(IDASDK)/lib/$(PLATFORM)
        LDFLAGS += -L$(LIBDIR) -lida
    endif
endif

# Default object extension
OBJ_EXT ?= .o

# Output directories
OBJDIR = obj/$(PLATFORM)
BINDIR = bin/$(PLATFORM)

# Object files
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%$(OBJ_EXT))

# Target plugin
PLUGIN = $(BINDIR)/$(PLUGIN_NAME)$(PLUGIN_EXT)

# Targets
.PHONY: all clean install dirs

all: dirs $(PLUGIN)

dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)

# Build plugin
$(PLUGIN): $(OBJECTS)
	@echo "Linking $@..."
ifdef MSVC
	$(CXX) $(OBJECTS) $(LDFLAGS) /OUT:$@
else
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@
endif
	@echo "Plugin built: $@"

# Compile source files
$(OBJDIR)/%$(OBJ_EXT): $(SRCDIR)/%.cpp
	@echo "Compiling $<..."
ifdef MSVC
	$(CXX) $(CXXFLAGS) /c $< /Fo$@
else
	$(CXX) $(CXXFLAGS) -c $< -o $@
endif

# Install to IDA plugins directory
install: $(PLUGIN)
	@echo "Installing plugin..."
	@if [ -n "$$IDA_DIR" ]; then \
		cp $(PLUGIN) "$$IDA_DIR/plugins/"; \
		echo "Installed to $$IDA_DIR/plugins/"; \
	else \
		echo "IDA_DIR not set. Please copy $(PLUGIN) to your IDA plugins directory."; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf obj bin
	@echo "Clean complete"

# Debug build
debug: CXXFLAGS += -g -DDEBUG -O0
debug: all

# Release build with optimizations
release: CXXFLAGS += -O3 -DNDEBUG
release: all

# Platform-specific builds
mac: 
	@$(MAKE) all UNAME_S=Darwin

linux:
	@$(MAKE) all UNAME_S=Linux

windows:
	@$(MAKE) all MSVC=1

# Help
help:
	@echo "HexRaysCodeXplorer Build System"
	@echo "==============================="
	@echo "Targets:"
	@echo "  all      - Build the plugin (default)"
	@echo "  debug    - Build with debug symbols"
	@echo "  release  - Build with optimizations"
	@echo "  install  - Install to IDA plugins directory"
	@echo "  clean    - Remove build artifacts"
	@echo ""
	@echo "Platform targets:"
	@echo "  mac      - Build for macOS"
	@echo "  linux    - Build for Linux"
	@echo "  windows  - Build for Windows (MSVC)"
	@echo ""
	@echo "Variables:"
	@echo "  IDASDK   - Path to IDA SDK (current: $(IDASDK))"
	@echo "  IDA_DIR  - IDA installation directory for install target"
	@echo ""
	@echo "Current platform: $(PLATFORM)"
	@echo "Plugin will be: $(PLUGIN)"