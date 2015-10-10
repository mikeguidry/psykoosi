# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.3

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


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
CMAKE_COMMAND = /opt/local/bin/cmake

# The command to remove a file.
RM = /opt/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/mike/psykoosi

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/mike/psykoosi

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/opt/local/bin/ccmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/opt/local/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target list_install_components
list_install_components:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Available install components are: \"Unspecified\""
.PHONY : list_install_components

# Special rule for the target list_install_components
list_install_components/fast: list_install_components

.PHONY : list_install_components/fast

# Special rule for the target install
install: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/opt/local/bin/cmake -P cmake_install.cmake
.PHONY : install

# Special rule for the target install
install/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/opt/local/bin/cmake -P cmake_install.cmake
.PHONY : install/fast

# Special rule for the target install/strip
install/strip: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/opt/local/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip

# Special rule for the target install/strip
install/strip/fast: install/strip

.PHONY : install/strip/fast

# Special rule for the target install/local
install/local: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/opt/local/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local

# Special rule for the target install/local
install/local/fast: install/local

.PHONY : install/local/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/mike/psykoosi/CMakeFiles /Users/mike/psykoosi/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/mike/psykoosi/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named capstone-shared

# Build rule for target.
capstone-shared: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 capstone-shared
.PHONY : capstone-shared

# fast build rule for target.
capstone-shared/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/capstone-shared.dir/build.make depends/capstone/CMakeFiles/capstone-shared.dir/build
.PHONY : capstone-shared/fast

#=============================================================================
# Target rules for targets named capstone-static

# Build rule for target.
capstone-static: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 capstone-static
.PHONY : capstone-static

# fast build rule for target.
capstone-static/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/capstone-static.dir/build.make depends/capstone/CMakeFiles/capstone-static.dir/build
.PHONY : capstone-static/fast

#=============================================================================
# Target rules for targets named test

# Build rule for target.
test: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test
.PHONY : test

# fast build rule for target.
test/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test.dir/build.make depends/capstone/CMakeFiles/test.dir/build
.PHONY : test/fast

#=============================================================================
# Target rules for targets named test_arm

# Build rule for target.
test_arm: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_arm
.PHONY : test_arm

# fast build rule for target.
test_arm/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_arm.dir/build.make depends/capstone/CMakeFiles/test_arm.dir/build
.PHONY : test_arm/fast

#=============================================================================
# Target rules for targets named test_arm64

# Build rule for target.
test_arm64: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_arm64
.PHONY : test_arm64

# fast build rule for target.
test_arm64/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_arm64.dir/build.make depends/capstone/CMakeFiles/test_arm64.dir/build
.PHONY : test_arm64/fast

#=============================================================================
# Target rules for targets named test_arm_regression

# Build rule for target.
test_arm_regression: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_arm_regression
.PHONY : test_arm_regression

# fast build rule for target.
test_arm_regression/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_arm_regression.dir/build.make depends/capstone/CMakeFiles/test_arm_regression.dir/build
.PHONY : test_arm_regression/fast

#=============================================================================
# Target rules for targets named test_detail

# Build rule for target.
test_detail: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_detail
.PHONY : test_detail

# fast build rule for target.
test_detail/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_detail.dir/build.make depends/capstone/CMakeFiles/test_detail.dir/build
.PHONY : test_detail/fast

#=============================================================================
# Target rules for targets named test_iter

# Build rule for target.
test_iter: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_iter
.PHONY : test_iter

# fast build rule for target.
test_iter/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_iter.dir/build.make depends/capstone/CMakeFiles/test_iter.dir/build
.PHONY : test_iter/fast

#=============================================================================
# Target rules for targets named test_mips

# Build rule for target.
test_mips: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_mips
.PHONY : test_mips

# fast build rule for target.
test_mips/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_mips.dir/build.make depends/capstone/CMakeFiles/test_mips.dir/build
.PHONY : test_mips/fast

#=============================================================================
# Target rules for targets named test_ppc

# Build rule for target.
test_ppc: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_ppc
.PHONY : test_ppc

# fast build rule for target.
test_ppc/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_ppc.dir/build.make depends/capstone/CMakeFiles/test_ppc.dir/build
.PHONY : test_ppc/fast

#=============================================================================
# Target rules for targets named test_skipdata

# Build rule for target.
test_skipdata: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_skipdata
.PHONY : test_skipdata

# fast build rule for target.
test_skipdata/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_skipdata.dir/build.make depends/capstone/CMakeFiles/test_skipdata.dir/build
.PHONY : test_skipdata/fast

#=============================================================================
# Target rules for targets named test_sparc

# Build rule for target.
test_sparc: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_sparc
.PHONY : test_sparc

# fast build rule for target.
test_sparc/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_sparc.dir/build.make depends/capstone/CMakeFiles/test_sparc.dir/build
.PHONY : test_sparc/fast

#=============================================================================
# Target rules for targets named test_systemz

# Build rule for target.
test_systemz: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_systemz
.PHONY : test_systemz

# fast build rule for target.
test_systemz/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_systemz.dir/build.make depends/capstone/CMakeFiles/test_systemz.dir/build
.PHONY : test_systemz/fast

#=============================================================================
# Target rules for targets named test_x86

# Build rule for target.
test_x86: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_x86
.PHONY : test_x86

# fast build rule for target.
test_x86/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_x86.dir/build.make depends/capstone/CMakeFiles/test_x86.dir/build
.PHONY : test_x86/fast

#=============================================================================
# Target rules for targets named test_xcore

# Build rule for target.
test_xcore: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_xcore
.PHONY : test_xcore

# fast build rule for target.
test_xcore/fast:
	$(MAKE) -f depends/capstone/CMakeFiles/test_xcore.dir/build.make depends/capstone/CMakeFiles/test_xcore.dir/build
.PHONY : test_xcore/fast

#=============================================================================
# Target rules for targets named pe_bliss

# Build rule for target.
pe_bliss: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 pe_bliss
.PHONY : pe_bliss

# fast build rule for target.
pe_bliss/fast:
	$(MAKE) -f depends/pe_bliss/CMakeFiles/pe_bliss.dir/build.make depends/pe_bliss/CMakeFiles/pe_bliss.dir/build
.PHONY : pe_bliss/fast

#=============================================================================
# Target rules for targets named udis86

# Build rule for target.
udis86: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 udis86
.PHONY : udis86

# fast build rule for target.
udis86/fast:
	$(MAKE) -f depends/udis86/CMakeFiles/udis86.dir/build.make depends/udis86/CMakeFiles/udis86.dir/build
.PHONY : udis86/fast

#=============================================================================
# Target rules for targets named fuzz

# Build rule for target.
fuzz: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 fuzz
.PHONY : fuzz

# fast build rule for target.
fuzz/fast:
	$(MAKE) -f psykoosi/CMakeFiles/fuzz.dir/build.make psykoosi/CMakeFiles/fuzz.dir/build
.PHONY : fuzz/fast

#=============================================================================
# Target rules for targets named psykoosi

# Build rule for target.
psykoosi: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 psykoosi
.PHONY : psykoosi

# fast build rule for target.
psykoosi/fast:
	$(MAKE) -f psykoosi/CMakeFiles/psykoosi.dir/build.make psykoosi/CMakeFiles/psykoosi.dir/build
.PHONY : psykoosi/fast

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... list_install_components"
	@echo "... install"
	@echo "... install/strip"
	@echo "... install/local"
	@echo "... test_arm_regression"
	@echo "... test_xcore"
	@echo "... test_systemz"
	@echo "... test_arm"
	@echo "... test_arm64"
	@echo "... test_iter"
	@echo "... test_detail"
	@echo "... test_x86"
	@echo "... test_sparc"
	@echo "... test_ppc"
	@echo "... test"
	@echo "... test_skipdata"
	@echo "... capstone-shared"
	@echo "... test_mips"
	@echo "... capstone-static"
	@echo "... pe_bliss"
	@echo "... udis86"
	@echo "... fuzz"
	@echo "... psykoosi"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system
