# SPDX-License-Identifier: GPL-2.0-only
# Copyright Epic Games, Inc. All Rights Reserved.
cmake_minimum_required(VERSION 3.22)
project(LinuxUEKernelTools)

find_program(CLANG_EXECUTABLE clang REQUIRED)
find_program(LLC_EXECUTABLE   llc   REQUIRED)
find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)

function(build_bpf BPF_FILE_SRC)
	get_filename_component(BPF_FILENAME ${BPF_FILE_SRC} NAME_WE)
	set(BPF_FILE_BYTECODE ${BPF_FILENAME}.bc)
	set(BPF_FILE_UNLINKED ${BPF_FILENAME}.unlinked.o)
	set(BPF_FILE_LINKED ${BPF_FILENAME}.linked.o)
	set(BPF_FILE_SKELETON ${BPF_FILENAME}.skel.h)

	add_custom_command(
		OUTPUT ${BPF_FILE_SKELETON}

		COMMAND ${CLANG_EXECUTABLE} ARGS
			${BPF_FILE_SRC}
			-o ${BPF_FILE_BYTECODE}
			-g
			-O3
			-Wall
			-I${CMAKE_CURRENT_BINARY_DIR}
			-target bpf
			-S
			-emit-llvm

		# use mcpu=probe to probe vm instruction set
		COMMAND ${LLC_EXECUTABLE} ARGS
			${BPF_FILE_BYTECODE}
			-o ${BPF_FILE_UNLINKED}
			-march=bpf
			-mcpu=probe
			-filetype=obj

		COMMAND ${BPFTOOL_EXECUTABLE} ARGS
			gen object
			${BPF_FILE_LINKED}
			${BPF_FILE_UNLINKED}

		COMMAND /bin/sh -c
			"${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_FILE_LINKED} name ${BPF_FILENAME} > ${BPF_FILE_SKELETON}"

		VERBATIM

		DEPENDS
			${BPF_FILE_SRC}
			${CMAKE_CURRENT_SOURCE_DIR}/LinuxUEKernelToolsShared.h
			${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h

		# bpftool seems to be crashing when trying to run in parallel
		JOB_POOL one_job
	)
	set_source_files_properties(${BPF_FILE_SKELETON} PROPERTIES GENERATED TRUE)
	target_sources(LinuxUEKernelTools PRIVATE ${BPF_FILE_SKELETON})
endfunction()

set_property(GLOBAL PROPERTY JOB_POOLS one_job=1)

add_executable(LinuxUEKernelTools LinuxUEKernelTools.cpp)

# autogen vmlinux.h
add_custom_command(
	OUTPUT vmlinux.h

	COMMAND ${BPFTOOL_EXECUTABLE} ARGS
		btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
)
set_source_files_properties(vmlinux.h PROPERTIES GENERATED TRUE)

# build bpfprogs
build_bpf(${CMAKE_CURRENT_SOURCE_DIR}/BPFProgs.c)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_library(LIBBPF_STATIC_LIBRARY
      NAMES libbpf.a
      HINTS ${LIBBPF_LIBRARY_DIRS}
	  NO_CMAKE_FIND_ROOT_PATH
      REQUIRED
)

target_link_directories(LinuxUEKernelTools PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(LinuxUEKernelTools PRIVATE ${LIBBPF_STATIC_LIBRARY} elf z)
target_include_directories(LinuxUEKernelTools PRIVATE ${LIBBPF_INCLUDE_DIRS})

# make sure the compiler can find gennerated files
target_include_directories(LinuxUEKernelTools PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_compile_definitions(LinuxUEKernelTools PRIVATE
	$<$<CONFIG:Debug>:DEBUG>
	$<$<CONFIG:Release>:RELEASE>
)
target_compile_options(LinuxUEKernelTools PRIVATE
	$<$<CONFIG:Debug>:-g -O0>
	$<$<CONFIG:Release>:-O3>
)