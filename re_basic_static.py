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
    return ['Error: Not yet implemented']


def extract_compile_info(exe_file_name):
    """
    find the compiler and compile time from an executable
    :param exe_file_name: string path to the executable
    :return: dict of compiler information
    """
    return {'Error': 'Not yet implemented'}


def eval_strings(exe_strings):
    """
    given a list of strings, find the strings that are of particular interest
    currently looks for IPs, URLs, file paths, and registry keys TODO
    return is in the form {'label': ['string_1', string_2', ...], ...}
    :param exe_strings: lst of strings
    :return: dict of lst of interesting strings
    """
    return {'Error': ['Not yet implemented']}


def eval_imports(exe_imports):
    """
    given a list of imports, filter for typical malware imports
    return is in the form {'label': ['import_1', 'import_2', ...], ...}
    :param exe_imports: lst of string imports
    :return: dict of lst of string imports
    """
    return {'Error': ['Not yet implemented']}


def main():
    """
    The primary function that is called
    Evaluates the commandline arguments, runs the appropriate functions, and prints the output
    :return: None
    """
    # Parse the arguments
    parser = argparse.ArgumentParser(description='A tool to simplify basic static analysis')
    parser.add_argument('exe_file_name', metavar='exe_file', type=str, help='The name of the exe file being evaluated')
    parser.add_argument('-c', '--compiler', action='store_true', help='enable compiler information search')
    parser.add_argument('-s', '--strings', action='store_true', help='enable string search')
    parser.add_argument('-n', '--note_string', action='store_true', help='enable noteworthy string parsing')
    parser.add_argument('-i', '--imports', action='store_true', help='enable import search')
    parser.add_argument('-m', '--note_imports', action='store_true', help='enable typical malware import parsing')
    parser.add_argument('-a', '--all', action='store_true', help='enable all modes')  # todo add option for an output
    parser.add_argument('--string-length', help='The minimum length of string to check for the strings section')
    args = parser.parse_args()

    # compiler section
    if args.compiler or args.all:
        print('\nCompiler information:\n')
        compile_info = extract_compile_info(args.exe_file_name)
        for label in compile_info:
            print(label, compile_info[label], sep=':')
        print('-'*100)

    # strings section
    if args.strings or args.all:
        print('\nStrings found:\n')
        if args.string_length:
            strings = extract_strings(args.exe_file_name, args.string_length)
        else:
            strings = extract_strings(args.exe_file_name)
        print(*(s for s in strings), sep='\n')
        print('-'*100)

    # noteworthy strings section
    if args.note_string or args.all:
        print('\nNoteworthy strings found:\n')
        if not args.strings and not args.all:
            if args.string_length:
                strings = extract_strings(args.exe_file_name, args.string_length)
            else:
                strings = extract_strings(args.exe_file_name)
        note_strings = eval_strings(strings)  # strings will be defined in the strings section or above statement
        print(*('{}:\n{}\n'.format(label, "\n".join(note_strings[label])) for label in note_strings), sep='\n')
        print('-'*100)

    # imports section
    if args.imports or args.all:
        print('\nImports found:\n')
        exe_imports = extract_imports(args.exe_file_name)
        print(*(i for i in exe_imports))
        print('-'*100)

    # noteworthy imports section
    if args.note_imports or args.all:
        print('\nTypical malware imports found:\n')
        if not args.imports and not args.all:
            exe_imports = extract_imports(args.exe_file_name)
        note_imports = eval_imports(exe_imports)  # imports will be defined in the imports section or above statement
        print(*('{}:\n{}\n'.format(label, "\n".join(note_imports[label])) for label in note_imports), sep='\n')
        print('-'*100)


if __name__ == '__main__':
    main()
