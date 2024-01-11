===========
CXI example
===========


    Introduction
    Content of the folder cxi_example
    Prerequisites
        Windows
        Linux
    Running the example 
        Windows
        Linux
    Compiling the example
        Windows
        Linux


Introduction
============

This folder contains an example for the CXI API.
 

Content of the folder ``cxi_example``
========================================

The directories have the following content:

bin     
        Compiled executables will be placed here. Go here to run one of the example program.
etc
        The cxi configuration file used in the example is located here. 
mak
        If you are a Linux user, you'll find a Makefile here, which allows you to compile the example. Adjust the ``Makefile`` to fit your system settings by editing the file ``config.inc``.
obj
        Object files are placed here when using the Makefile in folder ``mak``.
prj_14
        This folder contains Visual Studio 2015 project files. Executables will be placed in the folder ``bin``.  The envirnment variable ``%CS_PATH%`` is automatically set by the installer ``CryptoServerSetup.exe`` and used in the Visual Studio project files to locate the necessary libraries.
src
        The sample source file is found here.
 

Prerequisites
=============

We assume for all up-coming sections, that you've already done the following steps.

Windows
-------

You've already launched the Windows CryptoServerSetup installer on the CryptoServer product CD. 
The installer automatically sets the environment variable ``%CS_PATH%``. 
Make sure that you have write permissions on the sample folder and its subfolders when compiling and executing the example.  
Maybe you want to copy the example folder to a custom location.

Linux
-----

First copy from the CryptoServer product CD - depending on your system - either the folder ``Software/Linux/x86-32/Crypto_APIs/CXI`` or the folder  ``Software/Linux/x86-64/Crypto_APIs/CXI`` to a location, where you have write permissions. 
This location will be referred to as <your sample location>. You have as well already copied from the CD the folder ``Software/Linux/Simulator/sim5_linux`` (SecurityServer-CD) or ``SDK/linux`` (SDK-CD) to a location of your convenience. 
You've also payed attention, that you have write permissions on all files and folders in the new simulator location. 
This new simulator location will be referred to as <your simulator location>. 

 
Running the example
===================

For your convenience, the example is already available as exectuable in folder ``bin``. 

Windows
-------

We assume here, that you've already read the section Prerequisites.

If you want to use for test purposes the HSM simulator (an icon should have been place on your Desktop after installation), then make sure that the following line in the configuration file ``etc\cxi.cfg`` is set
 
    Device = 3001@127.0.0.1
    
Save the configuration file. Then start the HSM simulator by clicking on the simulator icon. 
Make sure that a cryptographic user with user name ``CXI_USER``, password ``utimaco`` and ``CXI_GROUP=test`` exists. (Use CAT or ``csadm`` to create it.)

Then go to folder ``bin``. Open a DOS command-line interface in folder ``bin`` and type:

    cxi_demo.exe cfg=..\etc\cxi.cfg

Linux
-----

We assume here, that you've already read the section Prerequisites.
 
If you want to use for test purposes the HSM simulator (an icon should have been place on your Desktop after installation), then make sure that the following line in the configuration file ``<your sample location>/sample/cxi_example/etc/cxi.cfg`` is set
 
    Device = 3001@127.0.0.1
    
Save the configuration file. Then go to ``<your simulator location>/bin`` and start the HSM simulator by calling ``cs_sim.sh`` in a terminal. 
Make sure that a cryptographic user with user name ``CXI_USER``, password ``utimaco`` and ``CXI_GROUP=test`` exists. (Use ``csadm`` to create it.)

Open another terminal and go to folder ``<your sample location>/sample/cxi_example/bin``. In folder ``bin`` type:

    ./cxi_demo cfg=../etc/cfg


Compiling the example
=====================

We assume here, that you've already read the section Prerequisites.

Windows
-------

Go to folder ``prj_14`` and open the file ``cxi_demo.sln`` with Visual Studio 2015.  
Pay attention under which platform (x64 or Win32) you are compiling. It has to fit your system architecture. 
You'll find your compiled executable in folder ``bin\<platform>``.

Linux
-----

In order to compile the sample files under Linux, use the ``Makefile`` in the folder ``<your sample location>/sample/cxi_example/mak``. Adjust the ``Makefile`` to fit your needs by editing the following variables in the file ``<your sample location>/sample/cxi_example/mak/config.inc``.

CC
            Adjust the path to your C++ compiler executable.
INC_DIR
            Adjust the path to the CXI header files (<your sample location>/include). 
LIB_PATH    
            Adjust the path to the CXI library (<your sample location>/lib).

Enter the folder ``<your sample location>/sample/cxi_example/mak``. Type ``make`` to compile all sample files. Type ``make clean`` to remove all executables and object files. 

You'll find the executable in folder ``<your sample location>/sample/cxi_example/bin/<platform>``.