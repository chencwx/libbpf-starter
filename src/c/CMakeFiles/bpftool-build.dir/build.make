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

# Utility rule file for bpftool-build.

# Include the progress variables for this target.
include CMakeFiles/bpftool-build.dir/progress.make

CMakeFiles/bpftool-build: bpftool/src/bpftool-stamp/bpftool-build


bpftool/src/bpftool-stamp/bpftool-build: bpftool/src/bpftool-stamp/bpftool-configure
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Performing build step for 'bpftool'"
	cd /home/cwx/桌面/libbpf-bootstrap/bpftool/src && make bootstrap OUTPUT=/home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/
	cd /home/cwx/桌面/libbpf-bootstrap/bpftool/src && /usr/bin/cmake -E touch /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp/bpftool-build

bpftool/src/bpftool-stamp/bpftool-configure: bpftool/tmp/bpftool-cfgcmd.txt
bpftool/src/bpftool-stamp/bpftool-configure: bpftool/src/bpftool-stamp/bpftool-update
bpftool/src/bpftool-stamp/bpftool-configure: bpftool/src/bpftool-stamp/bpftool-patch
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "No configure step for 'bpftool'"
	cd /home/cwx/桌面/libbpf-bootstrap/bpftool/src && /usr/bin/cmake -E echo_append
	cd /home/cwx/桌面/libbpf-bootstrap/bpftool/src && /usr/bin/cmake -E touch /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp/bpftool-configure

bpftool/src/bpftool-stamp/bpftool-update: bpftool/src/bpftool-stamp/bpftool-download
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "No update step for 'bpftool'"
	/usr/bin/cmake -E echo_append
	/usr/bin/cmake -E touch /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp/bpftool-update

bpftool/src/bpftool-stamp/bpftool-patch: bpftool/src/bpftool-stamp/bpftool-download
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "No patch step for 'bpftool'"
	/usr/bin/cmake -E echo_append
	/usr/bin/cmake -E touch /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp/bpftool-patch

bpftool/src/bpftool-stamp/bpftool-download: bpftool/src/bpftool-stamp/bpftool-mkdir
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "No download step for 'bpftool'"
	/usr/bin/cmake -E echo_append
	/usr/bin/cmake -E touch /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp/bpftool-download

bpftool/src/bpftool-stamp/bpftool-mkdir:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Creating directories for 'bpftool'"
	/usr/bin/cmake -E make_directory /home/cwx/桌面/libbpf-bootstrap/examples/c/../../bpftool/src
	/usr/bin/cmake -E make_directory /home/cwx/桌面/libbpf-bootstrap/examples/c/../../bpftool/src
	/usr/bin/cmake -E make_directory /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool
	/usr/bin/cmake -E make_directory /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/tmp
	/usr/bin/cmake -E make_directory /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp
	/usr/bin/cmake -E make_directory /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src
	/usr/bin/cmake -E make_directory /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp
	/usr/bin/cmake -E touch /home/cwx/桌面/libbpf-bootstrap/examples/c/bpftool/src/bpftool-stamp/bpftool-mkdir

bpftool-build: CMakeFiles/bpftool-build
bpftool-build: bpftool/src/bpftool-stamp/bpftool-build
bpftool-build: bpftool/src/bpftool-stamp/bpftool-configure
bpftool-build: bpftool/src/bpftool-stamp/bpftool-update
bpftool-build: bpftool/src/bpftool-stamp/bpftool-patch
bpftool-build: bpftool/src/bpftool-stamp/bpftool-download
bpftool-build: bpftool/src/bpftool-stamp/bpftool-mkdir
bpftool-build: CMakeFiles/bpftool-build.dir/build.make

.PHONY : bpftool-build

# Rule to build all files generated by this target.
CMakeFiles/bpftool-build.dir/build: bpftool-build

.PHONY : CMakeFiles/bpftool-build.dir/build

CMakeFiles/bpftool-build.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bpftool-build.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bpftool-build.dir/clean

CMakeFiles/bpftool-build.dir/depend:
	cd /home/cwx/桌面/libbpf-bootstrap/examples/c && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c /home/cwx/桌面/libbpf-bootstrap/examples/c/CMakeFiles/bpftool-build.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bpftool-build.dir/depend
