# Cheat Memory Driver

## Overview
This project implements a Windows kernel-mode driver that provides memory manipulation capabilities across processes. It uses a registry callback mechanism to receive commands from user-mode applications and perform various operations such as reading/writing memory, changing memory protection, allocating memory, and retrieving module base addresses.

## Security Notice
**WARNING**: This software is designed for educational purposes only. Using this driver in unauthorized ways may violate terms of service for games or applications and could potentially lead to bans or legal consequences.

## Technical Architecture

### High-Level Overview
The driver works by registering a callback for registry operations and intercepting specific registry write operations that contain command structures. These commands include a verification key (0x3c10bd66) to ensure only authorized applications can communicate with the driver. When a valid command is received, the driver performs the requested operation between the specified processes.

### Core Components

#### Registry Callback Mechanism
The driver uses Windows registry callback functionality to intercept registry operations. When a registry value is set with specific parameters matching the expected command structure, the driver processes the request.

#### Memory Operations
- **Read Memory**: Copy memory from a target process to the requesting process
- **Write Memory**: Copy memory from the requesting process to a target process
- **Change Protection**: Modify memory protection settings in the target process
- **Memory Allocation**: Allocate memory in the target process
- **Base Address Retrieval**: Get the base address of a process or specific modules

### Key Files

#### main.cpp
Contains the core driver functionality including:
- Registry callback implementation
- Memory operation handlers
- Driver entry point and initialization

#### shared_structs.hpp
Defines the data structures used for communication between user-mode applications and the driver:
- `operation_type` enum defining supported operations
- `operation` struct containing operation parameters
- `operation_command` struct for complete command information

#### utils.hpp
Provides utility functions for:
- Finding system modules and exports
- Process reference management
- Windows version detection
- PiDDB table cleaning (anti-detection mechanism)

#### windows_exports.hpp
Contains Windows structure definitions and function declarations needed for kernel operations.

#### fnv.hpp
Implements the FNV-1a hash algorithm used for string hashing operations.

#### xorstr.hpp
Provides string encryption at compile-time to obfuscate string literals in the binary.

#### pattern.hpp
Implements memory pattern scanning functionality to find specific byte patterns in memory.

#### raid_extension.hpp
Contains structure definitions related to RAID functionality, which appears to be used for certain driver operations.

## Technical Details

### Communication Protocol
The driver uses registry operations as a covert channel for communication. User-mode applications write specially crafted data to the registry, which the driver intercepts. The data includes:

1. A serial key (0x3c10bd66) for verification
2. Process IDs for both the requesting process and target process
3. Operation type and parameters
4. Address where the driver should write operation results

### Memory Operations Implementation

#### Read/Write Memory
Uses the `MmCopyVirtualMemory` kernel function to safely copy memory between processes.

#### Memory Protection
Attaches to the target process context using `KeStackAttachProcess` and calls `ZwProtectVirtualMemory` to change memory protection settings.

#### Memory Allocation
Attaches to the target process context and uses `ZwAllocateVirtualMemory` to allocate memory with specified protection.

#### Module Base Address Retrieval
Accesses the Process Environment Block (PEB) of the target process to enumerate loaded modules and find specific ones like "UnityPlayer.dll" or "GameAssembly.dll".

### Anti-Detection Mechanisms
The driver includes techniques to avoid detection:

1. String obfuscation using XOR encryption (via xorstr.hpp)
2. PiDDB table cleaning to hide driver loading information
3. Minimal footprint in registry operations

## Usage

This driver is designed to be loaded as a Windows kernel-mode driver. A user-mode application would communicate with it by writing specific data structures to the registry.

### Building

The project appears to be designed for building with Visual Studio. It likely requires the Windows Driver Kit (WDK) for compilation.

### Installation

As a kernel driver, installation requires:
1. Disabling driver signature enforcement or signing the driver
2. Loading the driver using the Service Control Manager

### User-Mode Integration

To communicate with the driver, a user-mode application would:
1. Create an `operation_command` structure with appropriate parameters
2. Set the verification key (0x3c10bd66)
3. Write this structure to a registry value
4. Read the results from the memory location specified in the command

## Security Considerations

- The driver operates with kernel privileges and can access any process memory
- The verification key provides minimal security and could be extracted from the binary
- No additional encryption is used for the memory operations themselves
- The driver could potentially be detected by anti-cheat systems

## Legal Disclaimer

This software is provided for educational purposes only. Usage of this driver to manipulate memory of applications without permission may violate terms of service and potentially laws depending on jurisdiction and usage.
