===========================
PKCS#11 Load Balancing Demo 
===========================
 

    Introduction
    Prerequisites
        For Windows
        For Linux
        For both operating systems
    Content of the folder demo_LoadBalancing
    Starting several HSM simulator instances
    Running the load balancing demo
        Configuring load balancing
        Synchronize the user databases
        Creating an 2048 bit RSA key pair
        Running the demo
    Compiling the load balancing demo
        Windows
        Linux
    References


Introduction
============

The folder ``<product CD>\Software\<OS>\<platform>\Crypto_APIs\PKCS11_R3\sample`` on the product CD contains an example which demonstrates Utimaco's load balancing feature. Although the following lines try to be complete, it is highly recommended to read the load balancing sections in the Manual for System Administrators [CSADMIN-LB] and the PKCS#11 developer guide [CSPKCS11].

The demo allows you to compare the time needed for a certain set of 2048 bit RSA key pair generation, sign or verify transactions between different cluster sizes. You can see how the computation time for the same set of transactions scales with cluster size.


Prerequisites
=============

We assume for all up-coming sections, that you've already done the following steps.

For Windows
-----------

1.  You've already launched the Windows CryptoServerSetup installer on the product CD. The installer automatically sets several environment variables, like  ``%CS_PKCS11_R3_CFG%`` and ``%CS_PATH%``

2.  If you are interested in using Utimaco's HSM simulator, then copy from the SecurityServer product CD the folder ``<product CD>/Software/Windows/Simulator/sim5_windows`` or from the CryptoServer SDK CD the folder ``<product CD>/SDK/Windows`` to a location of your convenience. This new simulator location will be referred to as <your simulator location>. Pay attention, that you have write permissions on all files and folders in the new locations. (Deactivate the read-only flag on the folder <your simulator location> and all its subfolders.)

For Linux
---------

1.  Copy from the product CD - depending on your system - either the folder ``<product CD>/Software/Linux/x86-32/Crypto_APIs/PKCS11_R3`` or the folder  ``<product CD>/Software/Linux/x86-64/Crypto_APIs/PKCS11_R3`` to a location, where you have write permissions. This location will be referred to as <your sample location>. 
2.  If you are interested in using Utimaco's HSM simulator, then copy from the SecurityServer product CD the folder ``<product CD>/Software/Linux/Simulator/sim5_linux`` or from the CryptoServer SDK CD the folder ``<product CD>/SDK/Linux`` to a location of your convenience. This new simulator location will be referred to as <your simulator location>. You've payed attention, that you have write permissions on all files and folders in the new locations.  

For both operating systems
--------------------------

The demo makes the following assumptions:

1.  You do have two running HSMs. If you are not interested in performance, but only in "how-it-works", then you can start several HSM simulator instances. (see below: `Starting several HSM simulator instances <#starting-several-hsm-simulator-instances>`__) Performance with HSM simulators is not at all comparable to that of real HSMs and depends on how busy your computer is with other applications at the moment of running the demo. For hardware HSMs you reach the best balancing result if you use HSMs of same model type. 

2.  You configured the PKCS#11 interface to use an external keystore. (see below: `Configuring load balancing <#configuring-load-balancing>`__)

3.  All HSMs in the cluster have the following identical user configuration:  A PKCS#11 Security Officer and a USER exist on slot 0 and they both have PIN ``123456``. (see below: `Synchronize the user databases <#synchronize-the-user-databases>`__)

4.  There exists an 2048 bit RSA key pair with **ID 0** (``CKA_ID=0``) for the USER on slot 0 in the external keystore.  (see below: `Creating an 2048 bit RSA key pair <#creating-an-2048-bit-rsa-key-pair>`__)


Content of the folder ``demo_LoadBalancing``
============================================

The directories have the following content:

``bin``        
        Compiled executables will be placed here. Go here to run the example.

``include``    
        The header file ``demo_LoadBalancing.h`` is located here.
``mak`` 
        If you are a Linux user, you'll find a Makefile here, which allows you to compile the example. Adjust the ``Makefile`` to fit your system settings by editing the file ``config.inc``.
``obj``
        The Makefile in folder ``mak`` expects this folder. Object files are placed here when building under Linux.
``prj_xx``
        These folders contain Visual C++ project files for compilation under Windows. Several Visual Studio versions are supported. Executables will be placed in the folder ``bin``. It expects the PKCS#11-header files to be placed in ``%CS_PATH%\Software\PKCS11_R3\include``. ``%CS_PATH%`` is automatically set by the installer ``CryptoServerSetup.exe``.
``src``
        The demo's source files are found here.
     

Starting several HSM simulator instances
========================================

We assume, that you have followed the simulator steps in section `Prerequisites <#prerequisites>`__.

Then go to the folder  ``<your simulator location>\bin`` and open (for Windows) a DOS command-line interface or (for Linux) a terminal. 

1. First we need to configure the simulator. According to section `Prerequisites <#prerequisites>`__ an SO and a USER both with PIN ``123456``, as well as an 2048 bit RSA key pair with ID 0 have to exist on slot 0. Therefore start the simulator with ``cs_sim.bat`` in the DOS window for Windows or with ``cs_sim.sh`` in the terminal for Linux. Make sure that the path to ``cs_pkcs11_R3.cfg`` is set correctly and that you've adapted the configuration file according to section `Configuring load balancing <#configuring-load-balancing>`__. The ``Device`` has to be set to ``3001@127.0.0.1``. Then use the graphical user interface P11CAT [CSP11CAT] to create the SO, the USER and the key. Close the simulator once you've finished.

2. Now we can "clone" the simulator configuration from the previous step. To start two identically configured simulators, simply type::

             cs_multi.bat 2   # [for Windows]
    
             cs_multi.sh 2    # [for Linux]

3. Use P11CAT to configure the simulator instance:
      1.	make sure that P11 cfg is properly edited (as described above)
      2.	make sure to have started two simulator instances (with cs_multi.bat 2) (cs_multi.bat is in CD Simulator/bin, for only one instance: use cs_sim.bat)
      3.	start P11CAT.jar (in CD Software/Administration, also csadm + CAT.jar there)
      4.	status text window should show: <date + time> P11 API initialized (if red text or many errors: most probably P11 cfg file is not containing proper Device = xx, furthermore the HSM/simulator needs to have an MBK loaded: check with csadm dev=xx mbklistkeys or with CAT: ManageMBK/Info tab)
      5.	click in left "Slot List" on slot 0 ("Slot ID 0000 0000") --> check status bar --> should show your defined devices -- these will be managed alltogether
      6.	click on Login/Logout icon in the toolbar at the top
      7.	the area below should show an active option "Login Generic", click on it
      8.	this should open further GUI fields --> enter "ADMIN" as user name, choose the "Keyfile" radio button and browse to the default ADMIN.key file (CD Software/Administration), click on the 'Login' button
      9.	now click on toolbar button "Slot Management" to initialize slot 0:
      10.	click on blue arrow "Init Token", this will also create SO_0000 user: enter the SO PIN (123456 needed for demo) and click on the 'Init Token' button below
      11.	now there's an SO (security office = kind of slots admin) click again on Login/Logout and on Login SO, note also the login status changes in 'Slot List' as well as the updates of the 'Status' text area
      12.	now click on Slot Management to create the slot user USER_0000:
      13.	click on blue arrow Init PIN (blue arrow) and define the user PIN ("123456" required for demo) -- note that the 'Set PIN' option is for changing the PIN
      •	note that you can at any time use the Restart button to reset the GUI state
      •	note that you sometimes first need to Login/Logout -> Logout All before you can login another user (e.g. for Login User to be enabled)
      14.	using Login User, log in slot 0 user (Slot ID 0000.0000 active, login status = 0000.0002)
      15.	click on Object Management to create/delete/manage keys per slot
      16.	click on Generate in the 'Object Management' area
      17.	choose Generate Key Pair, RSA - this will use default attributes, to add some specific attributes:
      18.	click on 'Create Attribute List' of the Public Key
      19.	in the 'Create Attribute List' dialog window, select 'CKA_ID', Add, and set 'Value' to 0, click OK -- note that alternatively, you can enter "CKA_ID=0" in the text field
      20.	repeat the same for the Private Key
      21.	check that the generated key pair is listed and the ID is set for both pub + prv 


4. Three identical instances are started with ``cs_multi.bat 3``, and so on. To close all instances simply hit <Return> on the window you started them from. With the closure all changes to the instances are lost. Next time you call ``cs_multi.bat 3`` the configuration in all three simulators will be the one configured in step 1. With the help of the ``cs_multi`` script there is no need to synchronize the HSM simulators (see below: `Synchronize the user databases <#synchronize-the-user-databases>`__). For real HSM devices, synchronization is necessary.

The device addresse of one simulator is ``3001@127.0.0.1``. A second simulator is referred to as ``3003@127.0.0.1``,  a third one as ``3005@127.0.0.1``, and so on.

     
Running the load balancing demo
===============================

For your convenience the executable is already available in folder ``bin``. Before running the demo, all points in section `Prerequisites <#prerequisites>`__ have to be fulfilled. Have a look at the following steps for help.

Configuring load balancing
--------------------------

The configuration of load balancing is done via the PKCS#11 configuration file ``cs_pkcs11_R3.cfg``.
Find first the location of your configuration file. In a DOS command-line window for Windows or a terminal for Linux type

::

    echo %CS_PKCS11_R3_CFG%   # [for Windows]
    
    echo $CS_PKCS11_R3_CFG    # [for Linux]
    
The path to the configuration file ``cs_pkcs11_R3.cfg`` will show up. If the variable is empty, then set it to the location of the PKCS#11 configuration file ``cs_pkcs11_R3.cfg``. A sample configuration file can be found in ``<product CD>\Software\<OS>\<platform>\Crypto_APIs\PKCS11_R3\sample`` directory.

First check that load balancing is set. Open the configuration file ``cs_pkcs11_R3.cfg`` in the location given by the environment variable and check whether ``FallbackInterval=`` is set to 0.

::

    # Configures load balancing mode ( == 0 ) or failover mode ( > 0 )
    FallbackInterval = 0

Then configure the external keystore. Set ``KeysExternal`` to ``true``, uncomment the line ``KeyStore=`` appropriate for your operating system (as an example below it is done for Windows) and choose path and keystore name.

::

    # Created/Generated keys are stored in an external or internal database
    KeysExternal = true

    # Path to the external keystore
    # If KeyStore is defined the external keystore will be created and used at the defined location
    # For unix:
    #KeyStore = /tmp/P11.pks
    # For windows:
    KeyStore = C:/tmp/P11.pks 
    
Then specify the IP addresses of the HSMs being part of your cluster in the configuration file. As an example here, the cluster has size 2 and the HSMs can be reached via IP address ``192.168.0.2`` and ``192.168.0.3``.

::

    [CryptoServer]
    # Device specifier (here: CryptoServer is CSLAN with IP address 192.168.0.1) 
    # Device = 192.168.0.1

    #[CryptoServer]
    # Device specifier (here: CryptoServer is logical failover device of CSLANs with IP 192.168.0.2 and IP 192.168.0.3) 
    Device = { 192.168.0.2 192.168.0.3 }

In case you want to test the load balancing demo on two running HSM simulator instances, then write down the port addresses of the two instances:

::

    [CryptoServer]
    # Device specifier (here: CryptoServer is CSLAN with IP address 192.168.0.1) 
    # Device = 192.168.0.1

    #[CryptoServer]
    # Device specifier (here: CryptoServer is logical failover device of CSLANs with IP 192.168.0.2 and IP 192.168.0.3) 
    Device = { 3001@127.0.0.1 3003@127.0.0.1 }


Synchronize the user databases
------------------------------

The demo assumes a Security Officer (SO) and a USER to exist on slot 0. Both have to have PIN ``123456``. Use the graphical user interface P11CAT [CSP11CAT] to create an SO and USER on slot 0.  Either you do this for every HSM in your cluster (by setting the ``Device=`` in the configuration file ``cs_pkcs11_R3.cfg``) or you use the graphical user interface administration tool CAT or the adminstration command-line tool ``csadm`` to backup and restore user databases. See the manual [CSADMIN-CAT] or [CSADM] for details.

Creating an 2048 bit RSA key pair
---------------------------------

Generate an 2048 bit RSA key pair with **ID 0** (``CKA_ID=0``) on slot 0 in the external keystore. This can, for example, be done by using the graphical user interface P11CAT [CSP11CAT]. As long as ``KeysExternal`` is set to ``true`` in the PKCS#11 configuration file ``cs_pkcs11_R3.cfg``, the key will be stored in the external database.

Running the demo
----------------

Once all the items in section `Prerequisites <#prerequisites>`__ have been fulfilled, you can start the demo. Make as well sure that your HSMs or HSM simulator instances are running.
 

Go to folder ``bin``.  The dynamic link library file is located  in ``%CS_PATH%\Lib\cs_pkcs11_R3.dll`` for Windows and ``<your sample location>/lib/libcs_pkcs11_R3.so`` for Linux. As an example we will perform 2 key pair generation, 10 sign and 20 verify transactions. (Change these as to fit your test interest.) Open in folder ``bin`` for Windows a DOS command-line interface or for Linux a terminal and type:

::

    demo_LoadBalancing.exe -LIB %CS_PATH%\Lib\cs_pkcs11_R3.dll  -keyGen 2 -sign 10 -verify 20   # [for Windows]
    
    demo_LoadBalancing -LIB <your sample location>/lib/libcs_pkcs11_R3.so  -keyGen 2 -sign 10 -verify 20   # [for Linux]



Compiling the load balancing demo
=================================

We assume here, that you've already read the section `Prerequisites <#prerequisites>`__. 

Windows
-------

Choose the Visual Studio Version of your choice. Go to the corresponding folder ``prj_xx`` and open the file ``PKCS11_HandsOn.sln`` with Visual C++.  The paths to the header files should already properly be set. The following header files are needed: ``cryptoki.h``, ``pkcs11.h``, ``pkcs11f.h``, ``pkcs11t.h``, ``pkcs11t_cs.h``, ``pkcs-11v2-20a3.h``, ``demo_LoadBalancing.h`` 

Pay attention under which platform (x64 or Win32) you are compiling. The dynamic library which you link at runtime has to match the platform you compiled for !

The executables will show up in the ``bin`` folder.

Linux
-----

In order to compile the sample files under Linux, use the ``Makefile`` in the folder ``<your sample location>/sample/demo_LoadBalancing/mak``. Adjust the ``Makefile`` to fit your needs by editing the following variables in the file ``<your sample location>/sample/demo_LoadBalancing/mak/config.inc``.

``CC``
            Adjust the path to your C compiler executable.
``INC_DIR_P11``
            Adjust the path to the PKCS#11 header files (``cryptoki.h``, ``pkcs11.h``, ``pkcs11f.h``, ``pkcs11t.h``, ``pkcs11t_cs.h``, ``pkcs-11v2-20a3.h``). 

Enter the folder ``<your sample location>/sample/demo_LoadBalancing/mak``. Type ``make`` to compile all sample files. Type ``make clean`` to remove all executables and object files. 

The executables are found in the ``<your sample location>/sample/demo_LoadBalancing/bin`` folder. 

References
==========

[CSADMIN-LB] 
        CryptoServer LAN / CryptoServer – Manual for System Administrators, Utimaco GmbH - Section "Clustering for Load Balancing and Failover"
[CSADMIN-CAT] 
        CryptoServer LAN / CryptoServer – Manual for System Administrators, Utimaco GmbH - Section "User Management"
[CSADM] 
        CryptoServer LAN / CryptoServer – Command-line Adminstration Tool - csadm, Utimaco GmbH
[CSP11CAT] 
        CryptoServer LAN / CryptoServer – PKCS#11 CryptoServer Administration Tool, Utimaco GmbH
[CSPKCS11] 
        CryptoServer PKCS#11 R3 Developer Guide, Utimaco GmbH - Section "Load Balancing Mode"




