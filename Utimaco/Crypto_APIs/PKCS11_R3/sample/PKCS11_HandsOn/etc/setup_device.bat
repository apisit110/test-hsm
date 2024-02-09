@echo on

rem This is a dummy file for Load_balancing

rem The script is used for preparing the device and setting the users and key pairs needed to execute the sample
rem Note: The $1 parameter is used as a value to pass the device name.. For example: 3001@127.0.0.1


rem There are two parameters %1% and %2%
set auth=logonsign=ADMIN,%1%

rem --CREATE USERS

rem select SIM_1
set CRYPTOSERVER=%2%

rem Try to delete user in case they already exist: (to avoid error when adding the user)
csadm %auth% deleteuser=CXI_USER >NUL 2>&1

rem add needed users csadm %auth% adduser=SO_0000,0200{CXI_GROUP=SLOT_0000},hmacpwd,123456

csadm %auth% adduser=CXI_USER,00000002{CXI_GROUP=test},hmacpwd,utimaco