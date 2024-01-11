==========================
CXI Load Balancing Example
==========================


    Introduction
    Content of the folder ``cxi_example_LoadBalancing``
    Prerequisites
        Windows
        Linux
        Both
    Compiling the example
        Windows
        Linux
    Running the example
        Windows
        Linux



Introduction
============

This folder contains an example for the CXI API, demonstrating usage of Utimaco's cluster feature. The demonstration is teamed with a use case. Please read ``cxi_example_LoadBalancing\doc`` for further details on Utimaco's cluster feature and the specific use case. This document here describes only how to install, compile and run the example.
 

Content of the folder ``cxi_example_LoadBalancing``
===================================================

The directories have the following content:

bin     
        Compiled executables will be placed here. Go here to run one of the example program.
doc
        This folder contains a pdf-document describing Utimaco's cluster feature and the example's use case in more detail.
etc
        The cxi-API's (``cxi.cfg``) and the example's (``lb.cfg``) configuration files are located here. 
mak
        If you are a Linux user, you'll find a Makefile here. Adjust the ``Makefile`` to fit your system settings by editing the file ``config.inc``.
obj
        Object files are placed here when building under Linux.
prj_14
        This folder contains Visual Studio project files. Executables will be placed in the folder ``bin``.  The envirnment variable ``%CS_PATH%`` is automatically set by the installer ``CryptoServerSetup.exe`` and used in the Visual Studio project files to locate the necessary libraries.
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
This location will be referred to as <your sample location>. 
You have as well already copied from the CD either the folder ``Software/Linux/Simulator/sim5_linux`` (SecurityServer-CD) or ``SDK/linux`` (SDK-CD) to a location of your convenience. 
You've also payed attention, that you have write permissions on all files and folders in the new simulator location. 
This new simulator location will be referred to as <your simulator location>. 

Both
----

Configure the example. First set the devices you want to use. Specify their IP addresses or ports in ``etc/cxi.cfg``. 
Continue configuring the example by opening ``etc/lb.cfg``. It contains a lot of extensive comments. Read them. 

Make sure that a cryptographic user with user name ``myUSER``, password ``123456`` and ``CXI_GROUP=sample`` exists. (Use CAT or ``csadm`` to create it.)
Make sure you have an ECDSA or RSA key pair with name ``cxi LB key`` set up for ``CXI_GROUP=sample`` . (Use CAT or ``csadm`` and the ``cxitool`` to create the key pair.)

Compiling the example
=====================

We assume here, that you've already read the section Prerequisites.

Windows
-------

Go to the folder ``prj_14`` and open the file ``cxi_example_LoadBalancing.sln`` with Visual Studio 2008.  
Pay attention under which platform (x64 or Win32) you are compiling. It has to fit your system architecture. 

You'll find your compiled executable in folder ``bin\<platform>``.

Linux
-----

In order to compile the sample files under Linux, use the ``Makefile`` in the folder ``<your sample location>/sample/cxi_example_LoadBalancing/mak``. Adjust the ``Makefile`` to fit your needs by editing the following variables in the file ``<your sample location>/sample/cxi_example_LoadBalancing/mak/config.inc``.

CC
             Adjust the path to your C++ compiler executable.
INC_DIR_CXI
             Adjust the path to the CXI header files (<your sample location>/include). 
PATH_LIB    
             Adjust the path to the CXI library (<your sample location>/lib).

Enter the folder ``<your sample location>/sample/cxi_example_LaodBalancing/mak``. Type ``make`` to compile all sample files. Type ``make clean`` to remove all executables and object files. 

You'll find the executable in folder ``<your sample location>/sample/cxi_example_LoadBalancing/bin/<platform>``.



Running the example
===================


Windows
-------

We assume here, that you've already read the section Prerequisites and that you have sucessfully compiled the example.
If you want to use for test purposes the HSM simulator (an icon should have been place on your Desktop after installation), then make sure that the following line in the configuration file ``etc\cxi.cfg`` is set

    Device = 3001@127.0.0.1
    
Save the configuration file. Then start the HSM simulator by clicking on the simulator icon. 
Check that you've created user und key pair as specified in ``etc\lb.cfg``. If you want to start two identical simulator instances, then close the currently running simulator, go to either ``%CS_PATH%\SDK\bin`` or ``%CS_PATH%\Simulator\sim5_windows\bin``, open a command window there and type ``cs_multi.bat 2``. In the case of two running simulator instances, don't forget to set the line in ``etc\cxi.cfg`` to
 
    Device = 3001@127.0.0.1 3003@127.0.0.1

Once the HSM is running, user as well as key are set and the example has been configured in ``etc\lb.cfg``, then  go to folder ``bin\<platform>``. 
Open a DOS command-line interface in folder ``bin`` and type:
Pay attention the path to ``CxiConfigFile`` is correct.

    cxi_demo_LoadBalancing.exe cfg=..\etc\lb.cfg

Linux
-----

We assume here, that you've already read the section Prerequisites.
 
If you want to use for test purposes the HSM simulator, then make sure that the following line in the configuration file ``<your sample location>/sample/cxi_example_LoadBalancing/etc/cxi.cfg`` is set
 
    Device = 3001@127.0.0.1
    
Save the configuration file. Then go to ``<your simulator location>/bin`` and start the HSM simulator by calling ``cs_sim.sh`` in a terminal. 
Check that you've created user und key pair as specified in ``<your sample location>/sample/cxi_example_LoadBalancing/etc/lb.cfg``. 
If you want to start two identical simulator instances, then close the currently running simulator, go to ``<your simulator location>/bin`` and type ``cs_multi.bat 2``. In the case of two running simulator instances, don't forget to set the line in ``<your sample location>/sample/cxi_example_LoadBalancing/etc/cxi.cfg`` to

    Device = 3001@127.0.0.1 3003@127.0.0.1

Once the HSM is running, user as well as key are set and the example has been configured in ``etc\lb.cfg``, then open another terminal, go to folder ``<your sample location>/sample/cxi_sample_LoadBalancing/bin`` and type:
Pay attention the path to ``CxiConfigFile`` is correct.

    ./cxi_demo_LoadBalancing cfg=../etc/lb.cfg