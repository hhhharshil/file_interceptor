# file_interceptor
Intercept HTTP Request/Responses to intercept file downloads developed in Python3 

Ensure to set up IP tables prior to usage of the program which will route traffic correctly.

For MITM type attacks targeting a remote host. You will need to run an arp spoofer or any attack which will allow your computer to be in the middle of the communication.

Usage:
python3 file_int.py

Please go through the code and replace value in line 49 with the file that you want the user to get redirected to download :)
