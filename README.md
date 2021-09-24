# re_basic_static
A tool to simply basic static analysis in reverse engineering

# Dependencies
pip libraries:
pefile

# Usage
usage: re_basic_static.py [-h] [-c] [-s] [-n] [-i] [-m] [-a]
                          [--string-length STRING_LENGTH]
                          exe_file

A tool to simplify basic static analysis

positional arguments:
  exe_file              The name of the exe file being evaluated

optional arguments: <br>
  -h, --help            show this help message and exit<br>
  -c, --compiler        enable compiler information search<br>
  -s, --strings         enable string search<br>
  -n, --note_string     enable noteworthy string parsing<br>
  -i, --imports         enable import search<br>
  -m, --note_imports    enable typical malware import parsing<br>
  -a, --all             enable all modes<br>
  --out OUT             A file to save the output to<br>
  --string-length STRING_LENGTH
                        The minimum length of string to check for the strings 
                        section

# Configurations
## Noteworthy imports section
This section is controlled by a text file. By default, it's called
common_imports.txt. I went with a text file instead of a JSON
to make it easier to edit. The format is "dllname:the description
of the dll". Do not include ".dll" in the dll name, it's added
programmatically. The case doesn't matter, pefile reads them all
as upper case, so the program converts to caps automatically.

## Compiler information section
This section reads signatures from a text file. The text file in 
use here was found at: https://raw.githubusercontent.com/guelfoweb/peframe/5beta/peframe/signatures/userdb.txt

# Code Notes
## Function names
The functions in this project follow a very simple naming scheme. 
Other than main, which is the function called when the program is run on its own,
functions start with either `extract` or `eval`. Functions labeled as `extract`
require at a minimum the filename at a minimum because it scans the file itself.
Functions labeled as `eval` do not require the filename, but simply the informations
being evaluated. For example, `extract_strings` takes 2 positional arguments: exe_file_name
and min_len. This functions opens the executable itself and uses regex to find strings
of a minimum length. On the other hand, `eval_strings` takes one positional argument:
exe_strings. `eval_strings` also uses regex, but it doesn't open any files, it only checks
the strings you pass it. That means you can import this file and run any `eval` functions
without having a file, as long as you have the information.

## Data files
Currently the program uses 2 data files: `common_imports.txt` and `sigs.txt`. They are
used by the `eval_imports` and `extract_compile_info` functions respectively. 
The file paths are defined at the top of the file under the imports as global variables.
These files can be edited or you can make your own files and change the paths.
