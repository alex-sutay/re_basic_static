# file: re_basic_static.py
# author: Alex Sutay

# built-in imports
import re  # used to extract strings from exe
import argparse  # used to parse the commandline arguments
# pip libraries
import pefile  # used to read the pe headers of exe files


def extract_strings(exe_file_name, min_len=4):
    """
    find all of the strings within an executable file
    :param exe_file_name: string path to the executable
    :param min_len: the minimum length of string to find; defaults to 4
    :return: lst of strings
    """
    with open(exe_file_name, 'rb') as f:
        exe_data = f.read()
    pattern = b"[\x1f-\x7e]{" + str(min_len).encode() + b",}"
    byte_strings = re.findall(pattern, exe_data)
    return sorted(a.decode() for a in byte_strings)


def extract_imports(exe_file_name):
    """
    find all of the imports within an executable file
    :param exe_file_name: string path to the executable
    :return: lst of string names of imports
    """


def extract_compile_info(exe_file_name):
    """
    find the compiler and compile time from an executable
    :param exe_file_name: string path to the executable
    :return: dict of compiler information
    """


def eval_strings(exe_strings):
    """
    given a list of strings, find the strings that are of particular interest
    currently looks for IPs, URLs, file paths, and registry keys TODO
    return is in the form {'label': ['string_1', string_2', ...], ...}
    :param exe_strings: lst of strings
    :return: dict of lst of interesting strings
    """


def eval_imports(exe_imports):
    """
    given a list of imports, filter for typical malware imports
    return is in the form {'label': ['import_1', 'import_2', ...], ...}
    :param exe_imports: lst of string imports
    :return: dict of lst of string imports
    """


def main():
    """
    The primary function that is called
    Evaluates the commandline arguments, runs the appropriate functions, and prints the output
    :return: None
    """
    parser = argparse.ArgumentParser(description='A tool to simplify basic static analysis')
    parser.add_argument('exe_file_name', metavar='exe_file', type=str,
                        help='The name of the exe file being evaluated')
    parser.add_argument('--string-length', help='The minimum length of string to check for the strings section')
    args = parser.parse_args()
    print(extract_strings(args.exe_file_name, args.string_length) if args.string_length else extract_strings(args.exe_file_name))


if __name__ == '__main__':
    main()
