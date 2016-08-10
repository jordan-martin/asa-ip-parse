# Cisco ASA IP Address Parser

Python script to discover all references to a specific IP address in an ASA configuration


Usage information for asa_ip.py:  


     python asa_ip.py <i>arguments</i>


     -s [source configuration file]   ** Required **
     -o [output file]   ** Only used when a single IP address is provided **
     -i [IP Address]
     -l [IP Address List File]   ** One IP Address Per Line **


     Either <b>-i</b> or <b>-l</b> is required, but only one can be used



<b>Libraries Required:</b>  CiscoConfParse, IPAddress

