# Cisco ASA IP Address Parser

Python script to discover all references to a specific IP address in an ASA configuration


Usage information for asa_ip.py:  


     python asa_ip.py arguments


     -s [source configuration file]   ** Required **
     -o [output file]   ** Only used when a single IP address is provided **
     -i [IP Address]
     -l [IP Address List File]   ** One IP Address Per Line **


     Either -i or -l is required, but only one can be used



<b>Libraries Required:</b>  CiscoConfParse, IPAddress

This script was written using python 2.7 and will not work with python3.  The python3 ported version will be uploaded soon.

