# cami
C Asterisk Manager Interface

## About

This is C-AMI, or C Asterisk Manager Interface, an AMI library for Asterisk.

The program is named CAMI as it takes its cue from AMI libraries for other languages, such as PAMI, NAMI, and erlami. However, it is not affiliated with the Asterisk project (nor other AMI libraries).

## Compiling

You may simply statically compile your program with `cami.c` and include the CAMI header files where needed.

Alternately, you may build and install the library by running `make install`.

## Usage

C-AMI allows you to send arbitrary AMI Actions, although some convenience macros are included to make this easier.

A listener thread receives AMI events and responses from Asterisk. It will then execute a user-provided callback function. The callback function receives an `ami_event`.

When an action is sent to Asterisk, an `ami_response` is returned. An `ami_response` contains one or more `ami_event`s.

It is the user's responsibility to properly free responses and events when done with them. Please refer to the header files for further documentation and usage.

The general goal of C AMI is to make it easy to interface with AMI by providing a robust interface for sending/receiving data from Asterisk, but otherwise not to get in your way too much.

## Demo Program

This program is an AMI library that is designed to be included in a C program to add AMI functionality.

For demonstration purposes, a simple standalone program is also included. It is recommended that you consult this for an overview of how C-AMI can be used.

Assuming you have `gcc`, simply clone the repository and run `make examples` to compile the demo programs with C-AMI.

(You will likely want to update the connection details for your Asterisk system). Then run `./simpleami` to run.

## Contributions

Contributions are welcome and encouraged!

Please following the coding conventions adhered to in this program. The [Asterisk Coding Guidelines](https://wiki.asterisk.org/wiki/display/AST/Coding+Guidelines) are a good start.
