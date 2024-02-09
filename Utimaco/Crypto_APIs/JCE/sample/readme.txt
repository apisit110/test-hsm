===========
JCE example
===========


    Introduction
    Content of the folder sample
    Prerequisites
    Compiling the example
    Running the example


Introduction
============

This folder contains an example for the JCE Java API.
 

Content of the folder ``sample``
========================================

The directories have the following content:

bin               Compiled jar file will be placed here.
src               The sample source files are found here.
pom.xml           pom file to build the sample
CryptoServer.cfg  Configuration file
readme.txt        This readme file
rsa.key           RSA key
rsa_enc.key       Encrypted RSA key

Prerequisites
=============

We assume for all up-coming sections, that you've already done the following steps.

Both
----
jdk version greater or equal to 1.8.0_211-x64 installed
Apache Maven installed

Windows
-------

You've already launched the Windows CryptoServerSetup installer on the CryptoServer product CD. 
The installer automatically sets the environment variable ``%CS_PATH%``. 
Make sure that you have write permissions on the sample folder and its subfolders when compiling and executing the example.  
Maybe you want to copy the example folder to a custom location. This location will be referred to as <your sample location>. 

Linux
-----

First copy from the CryptoServer product CD the folder ``Software/Linux/x86-64/Crypto_APIs/JCE`` to a location, where you have write permissions. 
This location will be referred to as <your sample location>. 
You have as well already copied from the CD the folder ``Software/Linux/Simulator/sim5_linux`` (SecurityServer-CD) or ``SDK/linux`` (SDK-CD) to a location of your convenience. 
This new simulator location will be referred to as <your simulator location>. 
You've also payed attention, that you have write permissions on all files and folders in the new simulator location. 

Compiling the example
=====================

Windows
-------

Go to folder <your sample location>\JCE\sample`. Open a DOS command-line interface in folder ``sample`` and type:

cd <your sample location>\JCE\sample
mvn install:install-file -Dfile="C:\Program Files\Utimaco\SecurityServer\Lib\CryptoServerJCE.jar" -DgroupId=de.utimaco -DartifactId=cryptoserverjce -Dversion=1.71 -Dpackaging=jar
mvn clean install

Linux
-----

Go to folder <your sample location>/JCE/sample`. Open a new terminal and type:

cd <your sample location>/JCE/sample
mvn install:install-file -Dfile=../lib/CryptoServerJCE.jar -DgroupId=de.utimaco -DartifactId=cryptoserverjce -Dversion=1.71 -Dpackaging=jar
mvn clean install
 
Running the example
===================

For your convenience, the example is already available as jar file in folder ``bin``. 

Windows
-------

We assume here, that you've already read the section Prerequisites.

If you want to use for test purposes the HSM simulator (an icon should have been place on your Desktop after installation), then make sure that the following line in the configuration file ``CryptoServer.cfg`` is set

     Device = 3001@127.0.0.1

Save the configuration file. Then start the HSM simulator by clicking on the simulator icon. 

Create a CryptoServer user named JCE with HMAC password and permission 0x00000002{CXI_GROUP=*} (password: 123456).
(Use CAT or ``csadm`` to create it.)

Open a DOS command-line interface in folder ``sample`` and type: 

   java -cp <path to sample class>;<path to CryptoServerJCE.jar> defaults.<sample> 

e.g.
cd <your sample location>\JCE\sample
java -cp bin\samples.jar;"C:\Program Files\Utimaco\SecurityServer\Lib\CryptoServerCXI.jar" defaults.bench_RSA   

The following examples are available:
    bench_RSA
    cert_Import
    crypt_AES
    crypt_DES
    crypt_RSA
    hash
    hmac_AES
    hmac_DES
    key_Delete
    key_Generate
    key_Import
    key_List
    key_Wrap_AES
    key_Wrap_RSA
    mac_AES
    mac_DES
    prov_Info
    prov_Login
    sign_DSA
    sign_EC
    sign_RSA

Linux
-----

We assume here, that you've already read the section Prerequisites.
 
If you want to use for test purposes the HSM simulator (an icon should have been place on your Desktop after installation), then make sure that the following line in the configuration file ``<your sample location>/sample/cxi_example/etc/cxi.cfg`` is set

     Device = 3001@127.0.0.1

Save the configuration file. Then go to ``<your simulator location>/bin`` and start the HSM simulator by calling ``cs_sim.sh`` in a terminal. 

Create a CryptoServer user named JCE with HMAC password and permission 0x00000002{CXI_GROUP=*} (password: 123456).
(Use ``csadm`` to create it.)

Open another terminal and go to folder ``<your sample location>/JCE/sample``.

Execute the following command from the sample directory: 
   java -cp <path to sample class>:<path to CryptoServerJCE.jar> defaults.<sample> 

e.g.
cd <your sample location>/JCE/sample
java -cp bin/samples.jar:../lib/CryptoServerJCE.jar defaults.bench_RSA   

The following examples are available:
    bench_RSA
    cert_Import
    crypt_AES
    crypt_DES
    crypt_RSA
    hash
    hmac_AES
    hmac_DES
    key_Delete
    key_Generate
    key_Import
    key_List
    key_Wrap_AES
    key_Wrap_RSA
    mac_AES
    mac_DES
    prov_Info
    prov_Login
    sign_DSA
    sign_EC
    sign_RSA
