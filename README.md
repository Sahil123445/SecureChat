# SecureChat

SecureChat is a local messsage application built for interaction between multiple users. It has end to end encryption and is secure from many attacks such as replay attack, man-in-the-middle attack because it uses digital certificates for verification as well as HMAC, SHA256 for .

Usage

Pre requisites
* First make sure to download Python3.
* Have a virtual enviorment like Kali linux to run the code.

Running File
* Launch Server.py using Python3 in terminal.
* Launch two different instances of Client.py using Python3 in terminal.
* Login using user1 and user 2 respectively (passwords are as follow : user1 = 111, user2 = 222,  user3 = 333)
* You can now use @user2 or @user1 function to send a message from one chat instance to another chat instance. 
* This message will be transferred using secure HMAC as well as being verified using a digital certificate. 

General Information
* Upon running the code for the first time, there might be some errors due to after the certificte authority file being created not being used properly. To fix this simply close all the terminals and launch and run them again. 
* If upon running it says port 1337/1338 is in use, simply open the server.py file and ctrl+F the port number and change to it +/- 1, do the same in the client.py file. This occurs if the port is not properly closed after use. 
