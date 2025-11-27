# HexRaysCodeXplorer Architecture Diagram

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              HexRaysCodeXplorer Plugin                              │
│                           (IDA Pro C++ Analysis Plugin)                             │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          PLUGIN ENTRY POINT LAYER                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                         CodeXplorer.cpp                                      │   │
│  │  • init() - Plugin initialization                                           │   │
│  │  • PLUGIN structure - IDA descriptor                                        │   │
│  │  • Action handlers (10 hotkeys)                                             │   │
│  │  • Hexrays callbacks (HXCE_*)                                               │   │
│  │  • Batch mode support                                                       │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────┘
          │                    │                    │                    │
          ▼                    ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  Type Analysis   │ │ VTable Analysis  │ │   Code Graph     │ │    UI Layer      │
│     Layer        │ │     Layer        │ │     Layer        │ │                  │
└──────────────────┘ └──────────────────┘ └──────────────────┘ └──────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════

## Detailed Component Architecture

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           TYPE ANALYSIS & RECONSTRUCTION                            │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌────────────────────┐    ┌────────────────────┐    ┌────────────────────────┐    │
│  │ TypeReconstructor  │───▶│  TypeExtractor     │───▶│  ReconstructableType   │    │
│  │     .h/.cpp        │    │     .h/.cpp        │    │       .h/.cpp          │    │
│  ├────────────────────┤    ├────────────────────┤    ├────────────────────────┤    │
│  │ • Reconstruct C++  │    │ • Extract types    │    │ • Type representation  │    │
│  │   types from code  │    │   from functions   │    │ • Convert to C++       │    │
│  │ • Analyze vars     │    │ • Member analysis  │    │ • Member management    │    │
│  └────────────────────┘    └────────────────────┘    └────────────────────────┘    │
│                                       │                                             │
│                                       ▼                                             │
│                          ┌────────────────────────┐                                 │
│                          │   CtreeExtractor       │                                 │
│                          │      .h/.cpp           │                                 │
│                          ├────────────────────────┤                                 │
│                          │ • Extract/dump ctree   │                                 │
│                          │ • AST traversal        │                                 │
│                          └────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         VIRTUAL TABLE ANALYSIS LAYER                                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                        ObjectExplorer.h/.cpp                                 │   │
│  │                         (Core VTable Discovery)                              │   │
│  ├─────────────────────────────────────────────────────────────────────────────┤   │
│  │ • find_vtables()        - Pattern-based vtable scan                         │   │
│  │ • find_vtables_rtti()   - RTTI-based vtable discovery                       │   │
│  │ • get_vtbl_info()       - Extract vtable information                        │   │
│  │ • create_vtbl_struct()  - Create IDA struct types                           │   │
│  │ • search_objects()      - Main entry point                                  │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                             │
│                                       ▼                                             │
│         ┌─────────────────────────────────────────────────────────────┐            │
│         │              IObjectFormatParser (Interface)                 │            │
│         │          Abstract RTTI Parsing Interface                     │            │
│         └─────────────────────────────────────────────────────────────┘            │
│                    ┌──────────────┼──────────────┐                                 │
│                    ▼              ▼              ▼                                  │
│  ┌─────────────────────┐ ┌─────────────────┐ ┌─────────────────────┐               │
│  │MSVCObjectFormatParser│ │GCCObjectFormat- │ │   ItaniumABI        │               │
│  │      .h/.cpp        │ │  Parser.h/.cpp  │ │     .h/.cpp         │               │
│  ├─────────────────────┤ ├─────────────────┤ ├─────────────────────┤               │
│  │ • MSVC RTTI parsing │ │ • GCC RTTI      │ │ • Itanium ABI       │               │
│  │ • Type descriptors  │ │ • type_info     │ │ • Modern C++ ABI    │               │
│  │ • CompleteObjectLoc │ │ • class_type_   │ │ • Thunk functions   │               │
│  │ • Base class desc   │ │   info structs  │ │ • Virtual bases     │               │
│  └─────────────────────┘ └─────────────────┘ └─────────────────────┘               │
│                    │              │              │                                  │
│                    └──────────────┼──────────────┘                                 │
│                                   ▼                                                 │
│                    ┌─────────────────────────────┐                                  │
│                    │   CompilerRTTIParser        │                                  │
│                    │        .h/.cpp              │                                  │
│                    ├─────────────────────────────┤                                  │
│                    │ • Unified RTTI interface    │                                  │
│                    │ • Compiler detection        │                                  │
│                    │ • RTTIInfo structure        │                                  │
│                    └─────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          CODE STRUCTURE ANALYSIS LAYER                              │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌────────────────────────┐              ┌────────────────────────┐                 │
│  │  CtreeGraphBuilder     │              │  ClassHierarchyGraph   │                 │
│  │       .h/.cpp          │              │       .h/.cpp          │                 │
│  ├────────────────────────┤              ├────────────────────────┤                 │
│  │ • callgraph_t class    │              │ • Inheritance detect   │                 │
│  │ • graph_builder_t      │              │ • Graph visualization  │                 │
│  │ • AST traversal        │              │ • Hierarchy display    │                 │
│  │ • Interactive graphs   │              └────────────────────────┘                 │
│  └────────────────────────┘                                                         │
│              │                                                                      │
│              ▼                                                                      │
│  ┌────────────────────────┐              ┌────────────────────────┐                 │
│  │  MicrocodeExtractor    │              │     CFIAnalyzer        │                 │
│  │       .h/.cpp          │              │         .h             │                 │
│  ├────────────────────────┤              ├────────────────────────┤                 │
│  │ • Low-level IR         │              │ • CFI scheme detect    │                 │
│  │ • Microcode analysis   │              │ • Virtual call checks  │                 │
│  │ • Maturity levels      │              │ • MSVC CFG/Clang CFI   │                 │
│  └────────────────────────┘              └────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           UI & VISUALIZATION LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│     ┌───────────────────────────────────────────────────────────────────────┐      │
│     │                      UI Selection (present_ui_choice)                  │      │
│     └───────────────────────────────────────────────────────────────────────┘      │
│                    │                    │                    │                      │
│                    ▼                    ▼                    ▼                      │
│  ┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐           │
│  │ ModernObjectExplorer│ │IntegratedTreeExplor-│ │ ImprovedObject-     │           │
│  │      .h/.cpp        │ │      er.h/.cpp      │ │   Explorer.h/.cpp   │           │
│  ├─────────────────────┤ ├─────────────────────┤ ├─────────────────────┤           │
│  │ • Table-based UI    │ │ • Tree hierarchy    │ │ • Classic list view │           │
│  │ • Sortable columns  │ │ • CH_HAS_DIRTREE    │ │ • Enhanced display  │           │
│  │ • Filter/search     │ │ • Inheritance view  │ │                     │           │
│  │ • chooser_t base    │ │ • Method grouping   │ │                     │           │
│  └─────────────────────┘ └─────────────────────┘ └─────────────────────┘           │
│                                   │                                                 │
│                                   ▼                                                 │
│  ┌─────────────────────┐ ┌─────────────────────────────────────────────────┐       │
│  │ TreeVTableExplorer  │ │            UnifiedObjectExplorer                │       │
│  │      .h/.cpp        │ │                  .h/.cpp                        │       │
│  ├─────────────────────┤ ├─────────────────────────────────────────────────┤       │
│  │ • VTableDirSpec     │ │ • Combined table/tree functionality             │       │
│  │ • VTableTreeBuilder │ │ • Export (JSON/CSV/C++ headers)                 │       │
│  │ • Segment grouping  │ │ • Regex search/filter                           │       │
│  │ • Namespace org     │ │ • Method cross-reference analysis               │       │
│  └─────────────────────┘ └─────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            UTILITY & SUPPORT LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
│  │  Common.h    │  │  Compat.h/   │  │  Utility.h/  │  │    Debug.h/.cpp      │    │
│  │              │  │    .cpp      │  │    .cpp      │  │                      │    │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────────────┤    │
│  │ • IDA SDK    │  │ • SDK ver-   │  │ • Compiler   │  │ • Logging infra      │    │
│  │   includes   │  │   sion compat│  │   detection  │  │ • Debug output       │    │
│  │ • Common     │  │ • API shims  │  │ • Helpers    │  │                      │    │
│  │   defines    │  │              │  │              │  │                      │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────────────┘    │
│                                                                                     │
│                          ┌────────────────────┐                                     │
│                          │     Linux.h        │                                     │
│                          ├────────────────────┤                                     │
│                          │ • Linux/Mac compat │                                     │
│                          │ • Platform macros  │                                     │
│                          └────────────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════

## Data Flow Diagram

┌─────────────────┐
│   IDA Pro       │
│   Binary Load   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              ANALYSIS PIPELINE                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐   │
│  │   SCAN       │────▶│   PARSE      │────▶│  ANALYZE     │────▶│   OUTPUT     │   │
│  │              │     │              │     │              │     │              │   │
│  │ • Pattern    │     │ • RTTI       │     │ • Type       │     │ • UI Display │   │
│  │   scan       │     │   parsing    │     │   reconstruct│     │ • IDA types  │   │
│  │ • RTTI       │     │ • VTable     │     │ • Hierarchy  │     │ • Export     │   │
│  │   detection  │     │   extract    │     │   analysis   │     │   files      │   │
│  └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘   │
│         │                    │                    │                    │           │
└─────────┼────────────────────┼────────────────────┼────────────────────┼───────────┘
          │                    │                    │                    │
          ▼                    ▼                    ▼                    ▼
   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
   │ vtbl_t_list │     │  RTTIInfo   │     │Reconstructed│     │  IDA Local  │
   │ (Global)    │     │ Structures  │     │   Types     │     │   Types     │
   └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘

═══════════════════════════════════════════════════════════════════════════════════════

## Key Data Structures

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              CORE DATA STRUCTURES                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────┐    ┌─────────────────────────────────────────┐    │
│  │       VTBL_info_t           │    │              RTTIInfo                    │    │
│  ├─────────────────────────────┤    ├─────────────────────────────────────────┤    │
│  │ qstring vtbl_name           │    │ CompilerType compiler (GCC/MSVC/Clang)  │    │
│  │ ea_t    ea_begin            │    │ ea_t         rtti_addr                  │    │
│  │ ea_t    ea_end              │    │ qstring      raw_name (mangled)         │    │
│  │ asize_t methods             │    │ qstring      class_name (demangled)     │    │
│  └─────────────────────────────┘    │ qvector<BaseClass> base_classes         │    │
│                                     │ bool has_virtual_base                   │    │
│                                     │ bool is_polymorphic                     │    │
│                                     └─────────────────────────────────────────┘    │
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                          method_info_t                                       │   │
│  ├─────────────────────────────────────────────────────────────────────────────┤   │
│  │ ea_t    address                   │ qstring name, demangled_name            │   │
│  │ ea_t    vtbl_entry_ea             │ bool    is_pure_virtual                 │   │
│  │ size_t  xref_count                │ bool    is_destructor                   │   │
│  │ qvector<ea_t> callers, callees    │ bool    is_virtual                      │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════

## Plugin Actions (Hotkeys)

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              REGISTERED ACTIONS                                     │
├────────────────┬───────────────────────────────────────────────────────────────────┤
│    Hotkey      │                        Action                                      │
├────────────────┼───────────────────────────────────────────────────────────────────┤
│  Ctrl-Alt-T    │  Display Ctree Graph - Visualize decompilation AST                │
│       O        │  Object Explorer - Main vtable browser (3 UI options)             │
│       R        │  REconstruct Type - Reconstruct C++ type under cursor             │
│       J        │  Jump to Disasm - Navigate to assembly view                       │
│       S        │  Extract Types to File - Dump all types                           │
│       C        │  Extract Ctrees to File - Dump all ctrees                         │
│       V        │  Ctree Item View - Show ctree representation                      │
│  Ctrl-Shift-M  │  Microcode View - Low-level IR visualization                      │
│       Q        │  Show/Copy Item Offset - WinDbg format                            │
│       E        │  Rename Vars - Auto-rename duplicated variables                   │
└────────────────┴───────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════

## Compiler Support Matrix

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              COMPILER SUPPORT                                       │
├─────────────┬───────────────────────┬───────────────────────────────────────────────┤
│  Compiler   │     Parser Module     │               Features                        │
├─────────────┼───────────────────────┼───────────────────────────────────────────────┤
│   MSVC      │ MSVCObjectFormat-     │ • Type descriptors                            │
│             │   Parser.h/.cpp       │ • Base class descriptors                      │
│             │ MSVCRTTIEnhanced      │ • Complete object locators                    │
│             │   .h/.cpp             │ • Class hierarchy descriptors                 │
├─────────────┼───────────────────────┼───────────────────────────────────────────────┤
│   GCC       │ GCCObjectFormat-      │ • type_info structures                        │
│             │   Parser.h/.cpp       │ • class_type_info                             │
│             │ GCCTypeInfo.h/.cpp    │ • Virtual inheritance support                 │
│             │ GCCVtableInfo.h/.cpp  │                                               │
├─────────────┼───────────────────────┼───────────────────────────────────────────────┤
│  Clang/     │ ItaniumABI.h/.cpp     │ • Itanium ABI vtable layout                   │
│  Modern     │                       │ • Thunk functions                             │
│             │                       │ • Virtual base adjustments                    │
└─────────────┴───────────────────────┴───────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════

## File Summary

┌────────────────────────────────────┬────────────────────────────────────────────────┐
│              File                  │                  Purpose                        │
├────────────────────────────────────┼────────────────────────────────────────────────┤
│ CodeXplorer.cpp                    │ Plugin entry, callbacks, action registration   │
│ ObjectExplorer.h/.cpp              │ Core vtable discovery and analysis             │
│ TypeReconstructor.h/.cpp           │ C++ type reconstruction from decompiled code   │
│ TypeExtractor.h/.cpp               │ Extract type info from functions               │
│ ReconstructableType.h/.cpp         │ Type representation and conversion             │
│ CtreeExtractor.h/.cpp              │ Extract/dump ctree (decompiler AST)            │
│ CtreeGraphBuilder.h/.cpp           │ Build/visualize call graphs                    │
│ MicrocodeExtractor.h/.cpp          │ Microcode (low-level IR) analysis              │
│ ClassHierarchyGraph.h/.cpp         │ Class inheritance visualization                │
│ MSVCObjectFormatParser.h/.cpp      │ MSVC-specific RTTI parsing                     │
│ GCCObjectFormatParser.h/.cpp       │ GCC-specific RTTI parsing                      │
│ ItaniumABI.h/.cpp                  │ Itanium C++ ABI support                        │
│ CompilerRTTIParser.h/.cpp          │ Unified RTTI parsing interface                 │
│ ModernObjectExplorer.h/.cpp        │ Modern table-based UI                          │
│ IntegratedTreeExplorer.h/.cpp      │ Tree hierarchy UI                              │
│ UnifiedObjectExplorer.h/.cpp       │ Comprehensive unified UI                       │
│ TreeVTableExplorer.h/.cpp          │ Alternative tree explorer                      │
│ ImprovedObjectExplorer.h/.cpp      │ Enhanced classic view                          │
│ CFIAnalyzer.h                      │ Control Flow Integrity analysis                │
│ Common.h / Compat.h / Utility.h    │ Support utilities and compatibility            │
└────────────────────────────────────┴────────────────────────────────────────────────┘
```

## Visual Component Interaction

```
                                    ┌──────────────────┐
                                    │     IDA Pro      │
                                    │   (Host App)     │
                                    └────────┬─────────┘
                                             │
                                    ┌────────▼─────────┐
                                    │  Hex-Rays API    │
                                    │  (Decompiler)    │
                                    └────────┬─────────┘
                                             │
     ┌───────────────────────────────────────┼───────────────────────────────────────┐
     │                                       ▼                                       │
     │                          ┌────────────────────────┐                           │
     │                          │   HexRaysCodeXplorer   │                           │
     │                          │    (Plugin Entry)      │                           │
     │                          └───────────┬────────────┘                           │
     │                                      │                                        │
     │           ┌──────────────────────────┼──────────────────────────┐             │
     │           │                          │                          │             │
     │           ▼                          ▼                          ▼             │
     │  ┌────────────────┐       ┌────────────────┐       ┌────────────────┐         │
     │  │ Type Analysis  │       │ VTable Engine  │       │   UI System    │         │
     │  │    Engine      │       │                │       │                │         │
     │  └───────┬────────┘       └───────┬────────┘       └───────┬────────┘         │
     │          │                        │                        │                  │
     │          ▼                        ▼                        ▼                  │
     │  ┌────────────────┐       ┌────────────────┐       ┌────────────────┐         │
     │  │Reconstructable │       │   RTTI Parser  │       │  Modern Table  │         │
     │  │    Type        │       │   (MSVC/GCC/   │       │  Tree Explorer │         │
     │  │                │       │    Itanium)    │       │  Unified View  │         │
     │  └────────────────┘       └────────────────┘       └────────────────┘         │
     │                                                                               │
     └───────────────────────────────────────────────────────────────────────────────┘
```
