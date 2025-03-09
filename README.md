# deAutoIt
A handy tool that automatically extracts the next stage of malware using AutoIt that decodes the next stage via known patterns encountered during analyses.


```
usage: deautoit.py [-h] [-s SCRIPT] [-a AUTOIT]

A tool to automate extraction of stage 2 of some cases of malware using AutoIt.

options:
  -h, --help           show this help message and exit
  -s, --script SCRIPT  Work directly on the script (deobfuscate strings before using it)
  -a, --autoit AUTOIT  extract the script and embedded files then work on them
  ```
