usage: passiveObserver10.py [-h] [--check-backups] file

Passive HTTP Observer - Analyze endpoints from Hellhound Spider JSON output.

positional arguments:
  file             Path to the Hellhound Spider JSON file.

options:
  -h, --help       show this help message and exit
  --check-backups  Enable lightweight probing for backup files (.bak, .old, etc.)

------------------------------------------------------------------------------------------------------

SUMMARY

To run the code, enter the below:

python3 passiveObserver10.py --check-backups <SPIDER HELLHOUND JSON FILENAME>