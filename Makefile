# See LICENSE.txt for license details.

CXX_FLAGS += -std=c++11 -O3 -Wall
PAR_FLAG = -fopenmp

ifneq (,$(findstring icpc,$(CXX)))
	PAR_FLAG = -openmp
endif

ifneq (,$(findstring sunCC,$(CXX)))
	CXX_FLAGS = -std=c++11 -xO3 -m64 -xtarget=native
	PAR_FLAG = -xopenmp
endif

ifneq ($(SERIAL), 1)
	CXX_FLAGS += $(PAR_FLAG)
endif

KERNELS = bc bfs cc cc_sv pr pr_spmv sssp tc
SUITE = $(KERNELS) converter

RING_SUFFIX = -ring
RING_FLAGS = -DGAPBS_CXL_SHM=1
RING_KERNELS = $(addsuffix $(RING_SUFFIX),$(KERNELS))

.PHONY: ring-secure
SECURE_SUFFIX = -ring-secure
SECURE_FLAGS = $(RING_FLAGS) -DGAPBS_CXL_SECURE=1
SECURE_LIBS = -lsodium
SECURE_KERNELS = $(addsuffix $(SECURE_SUFFIX),$(KERNELS))

.PHONY: all
all: $(SUITE)

% : src/%.cc src/*.h
	$(CXX) $(CXX_FLAGS) $< -o $@

.PHONY: ring
ring: $(RING_KERNELS)

%$(RING_SUFFIX) : src/%.cc src/*.h
	$(CXX) $(CXX_FLAGS) $(RING_FLAGS) $< -o $@

.PHONY: ring-secure
ring-secure: $(SECURE_KERNELS)

%$(SECURE_SUFFIX) : src/%.cc src/*.h
	$(CXX) $(CXX_FLAGS) $(SECURE_FLAGS) $< -o $@ $(SECURE_LIBS)

# Testing
include test/test.mk

# Benchmark Automation
include benchmark/bench.mk


.PHONY: clean
clean:
	rm -f $(SUITE) $(RING_KERNELS) $(SECURE_KERNELS) test/out/*
