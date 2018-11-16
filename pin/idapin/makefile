##
## PIN tools makefile for Linux
##
## For Windows instructions, refer to source/tools/nmake.bat and
## source/tools/Nmakefile
##
## To build the examples in this directory:
##
##   cd source/tools/ManualExamples
##   make all
##
## To build and run a specific example (e.g., inscount0)
##
##   cd source/tools/ManualExamples
##   make dir inscount0.test
##
## To build a specific example without running it (e.g., inscount0)
##
##   cd source/tools/ManualExamples
##   make dir obj-intel64/inscount0.so
##
## The example above applies to the Intel(R) 64 architecture.
## For the IA-32 architecture, use "obj-ia32" instead of
## "obj-intel64".
##

ifdef __X64__
    TARGET=ia32e
    BITNESS = 64
else
    TARGET=ia32
endif

##############################################################
#
# Here are some things you might want to configure
#
##############################################################

TARGET_COMPILER?=gnu
ifdef OS
    ifeq (${OS},Windows_NT)
        TARGET_COMPILER=ms
    endif
endif

##############################################################
#
# include *.config files
#
##############################################################

ifeq ($(TARGET_COMPILER),gnu)
    ifeq ($(wildcard makefile.gnu.config), )
        include ../makefile.gnu.config
    else
        include makefile.gnu.config
    endif
    CXXFLAGS ?= -g -Wall -Werror -Wno-unknown-pragmas $(DBG) $(OPT)
endif

ifeq ($(TARGET_COMPILER),ms)
    ifeq ($(wildcard makefile.ms.config), )
        include ../makefile.ms.config
    else
        include makefile.ms.config
    endif
    DBG?=
endif

##############################################################
#
# Tools sets
#
##############################################################

ifeq ($(TARGET),ia32e)
    BITNESS = 64
endif

TOOL_ROOTS = idadbg
STATIC_TOOL_ROOTS =

TOOLS = $(TOOL_ROOTS:%=$(F)%$(BITNESS)$(PINTOOL_SUFFIX))
STATIC_TOOLS = $(STATIC_TOOL_ROOTS:%=$(F)%$(SATOOL_SUFFIX))
SPECIAL_TOOLS = $(SPECIAL_TOOL_ROOTS:%=$(F)%$(PINTOOL_SUFFIX))
APPS_BINARY_FILES = $(APPS:%=$(F)%)

##############################################################
#
# build rules
#
##############################################################

# We build pintool with vs2010 because there is no yet vs2015 PIN libraries
ifeq ($(__VC15__),)
  GOAL=$(OUTDIR) make_all
else
  GOAL=v10
endif

.NOTPARALLEL:
v10:
	@../../../bin/v10.bat

all: $(GOAL)
test: make_test

ifneq ($(wildcard ../../../allmake.mak),)
  include ../../../allmake.mak
endif
ifneq ($(wildcard ../../../objdir.mak),)
  include ../../../objdir.mak
  OUTDIR=objdir
endif

make_all: make_tools
make_tools: $(TOOLS) $(STATIC_TOOLS) $(SPECIAL_TOOLS)
make_test: $(TOOL_ROOTS:%=%.test) $(STATIC_TOOL_ROOTS:%=%.test) $(SPECIAL_TOOL_ROOTS:%=%.test)

##############################################################
#
# build rules
#
##############################################################

$(APPS): $(OUTDIR)

$(F)%$(BITNESS).o : %.cpp makefile idadbg.h idadbg_local.h | $(OUTDIR)
	$(CXX) -c $(CXXFLAGS) $(PIN_CXXFLAGS) ${OUTOPT}$@ $<

$(TOOLS): $(PIN_LIBNAMES)

$(TOOLS): %$(PINTOOL_SUFFIX) : %.o
	${PIN_LD} $(PIN_LDFLAGS) $(LINK_DEBUG) ${LINK_OUT}$@ $< ${PIN_LPATHS} $(PIN_LIBS) $(DBG)

$(STATIC_TOOLS): $(PIN_LIBNAMES)

$(STATIC_TOOLS): %$(SATOOL_SUFFIX) : %.$(OBJEXT)
	${PIN_LD} $(PIN_SALDFLAGS) $(LINK_DEBUG) ${LINK_OUT}$@ $< ${PIN_LPATHS} $(SAPIN_LIBS) $(DBG)

DISTNAME=idapin
DISTFILES=idadbg.cpp idadbg.h idadbg_local.h \
          makefile makefile.gnu.config makefile.ms.config \
          IDADBG.sln IDADBG.vcxproj readme.txt

## make IDA PIN tool archive
distr: $(DISTNAME).zip

$(DISTNAME).zip: $(DISTFILES)
	mkdir -p $(DISTNAME)
	$(CP) $(DISTFILES) $(DISTNAME)
	zip -r $(DISTNAME).zip $(DISTNAME)/*

## cleaning
clean:
	-@rm -rf $(F) *.out *.log *.tested *.failed *.makefile.copy *.out.*.* *.o *.o64 $(DISTNAME).zip $(DISTNAME)
