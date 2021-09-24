# file: re_basic_static.py
# author: Alex Sutay

# built-in imports
import re  # used to extract strings from exe
import argparse  # used to parse the commandline arguments
import os.path  # used to check if the file exists
import datetime
# pip libraries
import pefile  # used to read the pe headers of exe files
import peutils  # used to read the signatures to find the compiler / packer


IMPORTS_DICT = "common_imports.txt"  # name of the file with common imports in it


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
    :return: dict of string names of dlls to string names of imports
    """
    pe = pefile.PE(exe_file_name)

    imports = dict()
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        imports[dll.dll.decode()] = [imp.name.decode() for imp in dll.imports]

    return imports


def extract_compile_info(exe_file_name):
    """
    find the compiler and compile time from an executable
    :param exe_file_name: string path to the executable
    :return: dict of compiler information
    """
    pe = pefile.PE(exe_file_name)
    rtn_dict = dict()

    sigs = peutils.SignatureDatabase('sigs.txt')
    matches = sigs.match_all(pe, ep_only=True)
    rtn_dict['Compiler'] = matches[0][0] if matches else 'Not recognized'

    compile_time = hex(pe.FILE_HEADER.TimeDateStamp)
    rtn_dict['Compile Time'] = str(datetime.datetime.utcfromtimestamp(float(int(compile_time, 16))))

    return rtn_dict


def eval_strings(exe_strings):
    """
    given a list of strings, find the strings that are of particular interest
    currently looks for IPs, URLs, file paths, and registry keys
    return is in the form {'label': ['string_1', string_2', ...], ...}
    :param exe_strings: lst of strings
    :return: dict of lst of interesting strings
    """
    rtn_dict = dict()

    paths = []
    files = []
    urls = []
    ips = []
    keys = []
    for string in exe_strings:
        if re.match(r'[a-zA-Z]:\\((?:.*?\\)*).*', string):
            paths.append(string)
        if re.match(r'([a-zA-Z0-9_/\\]+)\.(?!dll)(\w+)$', string):
            files.append(string)
        if re.match(r'(http|https)://[a-zA-Z./]+', string):
            urls.append(string)
        if re.match(r'^([0-9]+).+([0-9]+)[a-zA-Z./]*', string):
            ips.append(string)
        if re.match(r'HKEY[a-zA-Z/\\_]+', string):
            keys.append(string)
    if paths:
        rtn_dict['Possible Absolute File Paths'] = paths
    if files:
        rtn_dict['Possible File Names / Relative Paths'] = files
    if urls:
        rtn_dict['Possible urls'] = urls
    if keys:
        rtn_dict['Possible Registry Keys'] = keys

    if not rtn_dict:
        rtn_dict = {'Nothing found': ['No possible file paths, file names, urls, or IPs found']}

    return rtn_dict


def eval_imports(exe_imports):
    """
    given a list of imports, filter for typical malware imports
    return is in the form {'label': ['import_1', 'import_2', ...], ...}
    :param exe_imports: lst of string imports
    :return: dict of lst of string imports
    """
    with open(IMPORTS_DICT) as f:
        imports_dict = {line.split(':')[0].upper() + '.dll': line.split(':')[1].strip() for line in f}

    return_dict = dict()
    for dll in exe_imports:
        if dll in imports_dict:
            return_dict[imports_dict[dll] + ':\n' + dll] = exe_imports[dll]

    return return_dict


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
    parser.add_argument('-a', '--all', action='store_true', help='enable all modes')
    parser.add_argument('--out', help='A file to save the output to')
    parser.add_argument('--string-length', help='The minimum length of string to check for the strings section')
    args = parser.parse_args()

    # check if the file exists before continuing
    if not os.path.exists(args.exe_file_name):
        print(f'Could not find the file "{args.exe_file_name}"')
        return

    out_str = f'Basic Static analysis results for {args.exe_file_name}:\n'

    # compiler section
    if args.compiler or args.all:
        print('\nCompiler information:\n')
        out_str += '\nCompiler information:\n'
        try:
            compile_info = extract_compile_info(args.exe_file_name)
            for label in compile_info:
                print(label, compile_info[label], sep=': ')
                out_str += ':'.join([label, compile_info[label]]) + '\n'
        except Exception as e:
            print(f'An error occurred:\n{e}')
            out_str += f'An error occurred:\n{e}'
        finally:
            print('-' * 100)
            out_str += '-'*100 + '\n'

    # strings section
    if args.strings or args.all:
        print('\nStrings found:')
        out_str += '\nStrings found:\n\t'
        try:
            if args.string_length:
                strings = extract_strings(args.exe_file_name, args.string_length)
            else:
                strings = extract_strings(args.exe_file_name)
            print('', *(s for s in strings), sep='\n\t')
            out_str += '\n\t'.join(s for s in strings) + '\n'
        except Exception as e:
            print(f'An error occurred:\n{e}')
            out_str += f'An error occurred:\n{e}'
        finally:
            print('-' * 100)
            out_str += '-'*100 + '\n'

    # noteworthy strings section
    if args.note_string or args.all:
        print('\nNoteworthy strings found:\n')
        out_str += '\nNoteworthy strings found:\n'
        try:
            if not args.strings and not args.all:
                if args.string_length:
                    strings = extract_strings(args.exe_file_name, args.string_length)
                else:
                    strings = extract_strings(args.exe_file_name)
            note_strings = eval_strings(strings)  # strings will be defined in the strings section or above statement
            print(*('{}:\n\t{}\n'.format(lab, "\n\t".join(note_strings[lab])) for lab in note_strings), sep='\n')
            out_str += '\n'.join('{}:\n\t{}\n'.format(lab, "\n\t".join(note_strings[lab])) for lab in note_strings)
        except Exception as e:
            print(f'An error occurred:\n{e}')
            out_str += f'An error occurred:\n{e}'
        finally:
            print('-' * 100)
            out_str += '-'*100 + '\n'

    # imports section
    if args.imports or args.all:
        print('\nImports found:\n')
        out_str += '\nImports found:\n'
        try:
            exe_imports = extract_imports(args.exe_file_name)
            print(*('{}:\n\t{}\n'.format(label, "\n\t".join(exe_imports[label])) for label in exe_imports), sep='\n')
            out_str += '\n'.join('{}:\n\t{}\n'.format(label, "\n\t".join(exe_imports[label])) for label in exe_imports)
            out_str += '\n'
        except Exception as e:
            print(f'An error occurred:\n{e}')
            out_str += f'An error occurred:\n{e}'
        finally:
            print('-' * 100)
            out_str += '-'*100 + '\n'

    # noteworthy imports section
    if args.note_imports or args.all:
        print('\nTypical malware imports found:\n')
        out_str += '\nTypical malware imports found:\n'
        try:
            if not args.imports and not args.all:
                exe_imports = extract_imports(args.exe_file_name)
            note_imports = eval_imports(exe_imports)  # imports will be defined in the imports section or above
            print(*('{}\n\t{}\n'.format(lab, "\n\t".join(note_imports[lab])) for lab in note_imports), sep='\n')
            out_str += '\n'.join('{}:\n\t{}\n'.format(lab, "\n\t".join(note_imports[lab])) for lab in note_imports)
            out_str += '\n'
        except Exception as e:
            print(f'An error occurred:\n{e}')
            out_str += f'An error occurred:\n{e}'
        finally:
            print('-' * 100)
            out_str += '-'*100 + '\n'

    # save out_str if there was an output file selected
    if args.out:
        print(f'Saving to {args.out}...')
        try:
            with open(args.out, 'w') as f:
                f.write(out_str)
            print('Saved')
        except Exception as e:
            print(f'An error occurred while saving the file: {e}')


if __name__ == '__main__':
    main()
