# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/cwx/桌面/libbpf-bootstrap/examples/c

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/cwx/桌面/libbpf-bootstrap/examples/c

# Include any dependencies generated for this target.
include CMakeFiles/fentry.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/fentry.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/fentry.dir/flags.make

fentry.skel.h: fentry.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: fentry"
	bash -c "/home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/bootstrap/bpftool gen skeleton /home/cwx/桌面/libbpf-bootstrap/examples/c/fentry.bpf.o > /home/cwx/桌面/libbpf-bootstrap/examples/c/fentry.skel.h"

fentry.bpf.o: fentry.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: fentry"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/local/include -idirafter /usr/lib/llvm-10/lib/clang/10.0.0/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/home/cwx/桌面/libbpf-bootstrap/examples/c/../../vmlinux/x86 -isystem /home/cwx/桌面/libbpf-bootstrap/examples/c/libbpf -c /home/cwx/桌面/libbpf-bootstrap/examples/c/fentry.bpf.c -o /home/cwx/桌面/libbpf-bootstrap/examples/c/fentry.bpf.o

CMakeFiles/fentry.dir/fentry.c.o: CMakeFiles/fentry.dir/flags.make
CMakeFiles/fentry.dir/fentry.c.o: fentry.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/fentry.dir/fentry.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/fentry.dir/fentry.c.o   -c /home/cwx/桌面/libbpf-bootstrap/examples/c/fentry.c

CMakeFiles/fentry.dir/fentry.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/fentry.dir/fentry.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/cwx/桌面/libbpf-bootstrap/examples/c/fentry.c > CMakeFiles/fentry.dir/fentry.c.i

CMakeFiles/fentry.dir/fentry.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/fentry.dir/fentry.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/cwx/桌面/libbpf-bootstrap/examples/c/fentry.c -o CMakeFiles/fentry.dir/fentry.c.s

# Object files for target fentry
fentry_OBJECTS = \
"CMakeFiles/fentry.dir/fentry.c.o"

# External object files for target fentry
fentry_EXTERNAL_OBJECTS =

fentry: CMakeFiles/fentry.dir/fentry.c.o
fentry: CMakeFiles/fentry.dir/build.make
fentry: libbpf/libbpf.a
fentry: CMakeFiles/fentry.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable fentry"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/fentry.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/fentry.dir/build: fentry

.PHONY : CMakeFiles/fentry.dir/build

CMakeFiles/fentry.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/fentry.dir/cmake_clean.cmake
.PHONY : CMakeFiles/fentry.dir/clean

CMakeFiles/fentry.dir/depend: fentry.skel.h
CMakeFiles/fentry.dir/depend: fentry.bpf.o
	cd /home/cwx/桌面/libbpf-bootstrap/examples/c && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles/fentry.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/fentry.dir/depend

