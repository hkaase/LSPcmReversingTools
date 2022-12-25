# LSPcmReversingTools

This repository contains a selection of tools I found useful in approaching 0411 PCM disassembly. The knowledge for this is scattered everywhere, and I realized that if I was to ever lose my files on this I would have absolutely no idea where to begin again. 

Feel free to add to this, and it should continue growing as time goes on.

## CPU32 Folder

The CPU32 folder contains files that allow Ghidra to parse and understand the specific instructions used for this model of Motorola processor. Follow the readme file inside of it to install it to your Ghidra installation.

## PowerShell scripts

This repository contains a few PowerShell scripts. Usually, the names will be self-explanatory as to what they do. As of now, the scripts are mostly XDF conversion utilities, to help with disassembly. They parse information from an XDF file and automatically add relevant labels to Ghidra or IDA. 
