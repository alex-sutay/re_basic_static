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
  --string-length STRING_LENGTH
                        The minimum length of string to check for the strings 
                        section

<!--I'll add sections for use and function naming later-->

# Configurations
## noteworthy imports section
This section is controlled by a text file. By default, it's called
common_imports.txt. I went with a text file instead of a JSON
to make it easier to edit. The format is "dllname:the description
of the dll". Do not include ".dll" in the dll name, it's added
programmatically. The case doesn't matter, pefile reads them all
as upper case, so the program converts to caps automatically.