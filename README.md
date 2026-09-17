# Squall
A lightweight static-analysis vulnerability scanner

# Using the program
You can either run the program with "./squall.py" from the same directory as the files, or install the program to allow for it to be run from any directory. As part of the arguments to run the program, include the file/directory you wish to scan. To view all usable flags, run the command with the argument "-h" included.

# How it works
Squall parses through the provided file/directory, searching for any keywords defined in its ruleset. If it encounters a match, a rule has been violated, and it outputs the rule, the offending file, line number & line of code, a description of the rule, and a fix for the problem (if applicable).

Please note that it is possible for false positives, particularly with comment lines, but since the flagged line of code gets printed, you can identify false positives by checking the results.

Also, if you wish to add your own rules to the defined ruleset, you can! To do so, add them to rules.py and follow the format for definition _r.
