import argparse
import pathlib
import csv

# Interface class to display terminal messages (credits: //Rober)
import re
import time
import os


class Interface:
    def __init__(self):
        self._red = '\033[91m'
        self._cyan = '\033[1;36m'
        self._green = '\033[92m'
        self._white = '\033[37m'
        self._yellow = '\033[93m'
        self._bold = '\033[1m'
        self._end = '\033[0m'

    def clear(self):

        # for windows
        if os.name == 'nt':
            os.system('cls')
        # for mac and linux(here, os.name is 'posix')
        else:
            os.system('clear')

    def header(self):
        self.clear()
        print(f"            >> 🍇 {self._cyan}Low {self._red}Hanging {self._green}Fruiter{self._end} 🍇 <<  ")
        print('  Helper script for finding common code vulnerabilities\n')
        time.sleep(1)

    def info(self, message):
        new_message = f"[{self._white}*{self._end}] {message}"
        print(new_message)
        return new_message

    def warning(self, message):
        new_message = f"[{self._yellow}!{self._end}] {message}"
        print(new_message)
        return new_message

    def error(self, message):
        new_message = f"[{self._red}x{self._end}] {message}"
        print(new_message)
        return new_message

    def success(self, message):
        new_message = f"[{self._green}✓{self._end}] {self._bold}{message}{self._end}"
        print(new_message)
        return new_message

    def red(self, message):
        new_message = f"{self._red}{message}{self._end}"
        print(new_message)
        return new_message

    def yellow(self, message):
        new_message = f"{self._yellow}{message}{self._end}"
        print(new_message)
        return new_message

    def green(self, message):
        new_message = f"{self._green}{message}{self._end}"
        print(new_message)
        return new_message

    def cyan(self, message):
        new_message = f"{self._cyan}{message}{self._end}"
        print(new_message)
        return new_message

    def bold(self, message):
        new_message = f"{self._bold}{message}{self._end}"
        print(new_message)
        return new_message

    def remark(self, word, message):

        r_word = f"{self._red}{word}{self._end}"
        l_word = len(word)
        ix = message.lower().index(word.lower())

        new_message = self._end + self._cyan + message[:ix] + self._end + r_word + self._cyan + message[ix+l_word:] + self._end

        print(new_message)
        return new_message


class Finding:
    """
    Class which defines a finding. A finding is defined with:
        - Line number
        - Column Number
        - Line string
        - Word or phrase matched
        - Vulnerability object matched
        - Path of the file that contains vulnerability
    """
    def __init__(self, filepath, line_n, col_n, linestr, match, vuln):
        self.line_n = line_n
        self.col_n = col_n
        self.linestr = linestr
        self.match = match
        self.vuln = vuln
        self.path = filepath

    def print(self, simplified, n_vulns, quiet):
        """
        Function to print a finding
        :param simplified: If simplified output
        :param n_vulns: N of same vulns found
        :return:
        """
        i = Interface()
        if simplified:
            message = f"{self.path}///{self.line_n}///{self.linestr}///{n_vulns}"
            if not quiet:
                print(message)

        else:
            message = f"\t- Path: {self.path}" \
                      f"\n\t- Line number: {self.line_n}" \
                      f"\n\t- Column: {self.col_n}" \
                      f"\n\t- Description: {self.vuln.desc}" \
                      f"\n\t- Triggered regexp: {self.vuln.regexp}" \
                      f"\n\t- Severity: {self.vuln.level}"

            if not quiet:
                i.info(message)
                print("\t- Line: ", end='')
                i.remark(self.match, f"{self.linestr}\n")
            message += f"\n\t- Line: {self.linestr}\n"

        return message

class CargoCheck:

    def __init__(self, check_string, must_be_included):
        self.check_str = check_string
        self.mustbeincluded = must_be_included

class Vulnerability:
    """
    Class to define a possible vulnerability. It is described with a regular expression, a short description and a level
    of criticality
    """
    def __init__(self, regexp, description, level):
        self.regexp = regexp
        self.desc = description
        self.level = level

    def __str__(self):
        return "Vulnerability: " + self.regexp + "|" + self.desc + "|" + self.level


def find_vuln(vuln, filepath, ex_words):
    """
    Find just one kind of vulnerability on filepath.
    :param vuln: The vulnerability object to find
    :param filepath: The file to search into
    :param ex_words: Bad words to use when excluding lines
    :return: A list of findings [Finding, Finding,...]
    """
    findings = []
    line_n = 1

    filestream = read_rs_file(filepath)

    for line in filestream:

        matched = re.search(vuln.regexp, line)
        index = matched.span()[0] if matched is not None else None
        trimline = line.lower().lstrip(" \t") if line[-1] != '\n' else line.lower().lstrip(" \t")[:-1]

        if is_testing_part(filepath, trimline, "rust"):
            break

        # If our word is in line and does not start with / (is not a part of a comment)
        if (index is not None) and (not trimline.startswith("/")):
            # If there is no comment or if there is a comment and the matched pattern
            # is placed BEFORE comment tags (is not a part of a comment)
            comment_position = trimline.find("//")
            if (comment_position < 0) or (comment_position > 0 and index < comment_position):
                # if *variable is considered as mul. We have to check also for that specific syntax to avoid false positives
                if must_be_excluded(trimline, ex_words) or "if *" in matched.group():
                    line_n += 1
                    continue
                else:
                    findings.append(Finding(filepath, line_n, index, line.lstrip(" \t").rstrip("\n"), matched.group(), vuln))

        line_n += 1

    return findings


def find_everything(vulns, filepaths, ex_words, extension):
    """
    Method to find every incidence on every filepath. It reads line by line and tries to find matched regexp or custom
    words.
    :param vulns: List of Vulnerabilities: [Vulnerability, Vulnerablity,...]
    :param filepaths: List of filepaths
    :return: List of Findings [Finding, Finding,...]
    """
    total_findings = []
    for vuln in vulns:
        for file in filepaths:
            if not file.endswith(extension):
                continue
            found = find_vuln(vuln, file, ex_words)
            if found is not None:
                total_findings += found

    return total_findings


def must_be_excluded(line, ex_words):
    """
    Checks if exists excluded words/phrases in line
    :param line: The line to check in
    :param ex_words: Excluded words or prhases
    :return: True or False
    """
    for exclusion in ex_words:
        if exclusion in line and exclusion != "":
            return True
    return False


def is_testing_part(filepath, line, lang):
    """
    Checks if a test is starting
    :param filepath:
    :param line:
    :return:
    """
    if lang == "rust":
        test_tags = (
            "#[cfg(test)]",
            "#[test]",
            "mod tests"
        )

        if "/tests/" in filepath or line.startswith(test_tags) or filepath.endswith("tests.rs"):
            return True

        return False
    else:
        return False

def get_files_info(project_programs_path, extension, ex_paths):
    """
    Method to find all files and paths from a directory. It performs a recursive search whithing all childrens
    :param project_programs_path: Base path from where start searching. MUST BE ABSOLUTE.
    :param extension: Extension of files to find
    :return: A list of absolute filepaths []
    """
    filepaths = []
    for x in list(pathlib.Path(project_programs_path).glob('**/*.' + extension)):
        path = str(x.resolve())
        if not path.startswith(tuple(ex_paths)):
            filepaths.append(path)
    return filepaths

# Only for Rust
def get_cargo_files_info(project_programs_path, ex_paths):
    """
    Method to find all Cargo.toml files and paths from a directory. It performs a recursive search whithing all childrens
    :param project_programs_path: Base path from where start searching. MUST BE ABSOLUTE.
    :param extension: Extension of files to find
    :return: A list of absolute filepaths []
    """
    filepaths = []
    for x in list(pathlib.Path(project_programs_path).glob('**/Cargo.toml')):
        path = str(x.resolve())
        if not path.startswith(tuple(ex_paths)):
            filepaths.append(path)
    return filepaths

def read_vulns(file_path):
    """
    Method to read all vulns from a file
    :param file_path: The file to read from
    :return: A list of Vulnerabilities [Vulnerability, Vulnerability,...]
    """
    vulnlist = []

    with open(file_path, "r") as file:
        lines = csv.DictReader(file, delimiter=',')
        for line in lines:
            vulnlist.append(Vulnerability(line['regexp'], line['desc'], line['level']))

    return vulnlist

def read_cargo_checks(file_path):
    """
    Method to read all cargo checks from a file
    :param file_path: The file to read from
    :return: A list of checks [(check, <must_present|must_not>), (check, <must_present|must_not>), ...]
    """

    checkslist = []

    with open(file_path, "r") as file:
        lines = csv.DictReader(file, delimiter=',')
        for line in lines:
            checkslist.append((line['check'], line['must_be_present']))

    return checkslist

def read_rs_file(filepath):
    return open(filepath, "r").readlines()

def print_findings(findings, n_files, ofile, simplified, interface):
    """
    Function for printing results
    :param findings: A list of findings
    :param n_files: Total number of files processed
    :param ofile: Output file name
    :param simplified: If the printing must be simplified or not (boolean)
    :return: None
    """
    i = interface
    file = None

    if ofile:
        file = open(ofile, "w")

    n_findings = len(findings)

    group = group_vulns(findings)
    for find in group:

        i.info(f"Found {i._red}{find[1]}{i._end} incidences like the following:")
        find[0].print(simplified, find[1], False)

    for find in findings:
        message = find.print(simplified, 1, True)
        if file:
            file.write(message + "\n")

    if not simplified:
        i.success(f"Total findings: {n_findings} in {n_files} files")
        i.success(f"Number of different vulnerabilities: {len(group)}")
        i.warning("For details, please use this tool with -o option and check output file.\n")
        i.warning("NOTE: This is just a help for testing. Please, review each incidence manually.")


def print_cargo_findings(cargo_findings, interface):
    """
    Function for printing results
    :param findings: A list of findings
    :param n_files: Total number of files processed
    :param ofile: Output file name
    :param simplified: If the printing must be simplified or not (boolean)
    :return: None
    """
    i = interface

    n_findings = len(cargo_findings)

    if n_findings > 0:
        print("")
        i.info(f"*** ADITIONAL CARGO CHECKS ***")
        i.info(f"CARGO - Found {i._red}{n_findings}{i._end} incidences on the following files:")
        for find in cargo_findings:
            i.info(f"- Cargo file: {find[0]}")
            i.red(f"    - Check: {find[1][0]}")
            i.red(f"    - Must be present?: {find[1][1]}")

def group_vulns(findings):

    findings_map = []
    n_vuln = 1

    for i in range(0, len(findings)):
        # Last case
        if i == len(findings)-1:
            findings_map.append((findings[i], n_vuln))
        else:
            # If current vuln is the same as the following one
            if findings[i].vuln.regexp == findings[i+1].vuln.regexp:
                n_vuln += 1
            else:
                findings_map.append((findings[i], n_vuln))
                n_vuln = 1

    return findings_map


def check_cargo_files(cargo_paths, checks):
    """
    This function searches for a hardcoded array of vulnerabilities (potential_missings) and, if something is missing,
    it appends the check to missing_checks to return the values
    :param cargo_paths: Paths of all cargo files
    :return: vuln_checks: Array of pairs (cargopath, check(check_str, must_be_included))
    """
    vuln_checks = []

    for cargofile in cargo_paths:

        with open(cargofile, "r") as f:

            lines = f.readlines()

            for check in checks:

                check_str = check[0]

                for line in lines:
                    found = False
                    if check_str.lower().strip(" ") in line.lower().strip(" "):
                        found = True

                if (bool(check[1]) and not found) or (not bool(check[1]) and found):
                    vuln_checks.append((cargofile, check))

            f.close()

    return vuln_checks


if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(
        description='Simple and scalable script to find low hanging fruites in code reviews')
    # Add the arguments
    my_parser.add_argument('-p', '--path', required=True, type=str, help='Absolute path to search in')
    my_parser.add_argument('-v', '--vuln_conf', required=False, type=str, default="vuln_definition.conf",
                           help='Vulnerability descriptions file')
    my_parser.add_argument('-l', '--language', required=False, default="rust", help='Language to parse: rust or solidity')
    my_parser.add_argument('-ew', '--exclude-words', required=False, type=str, help='List of words, comma separated, '
                                                                             'to exclude from results if found')
    my_parser.add_argument('-ep', '--exclude-paths', required=False, type=str, help='List of paths, comma separated, '
                                                                                   'to exclude from results if found')
    my_parser.add_argument('-o', '--ofile', required=False, type=str, help='Regular output file')
    my_parser.add_argument('-s', '--simplified', required=False, default=False, action='store_true', help='Simplified greppeable output')

    args = my_parser.parse_args()

    if not args.simplified:
        Interface().header()

    ex_paths = ""
    if args.exclude_paths:
        try:
            ex_paths = args.exclude_paths.strip(" ").split(",")
        except:
            my_parser.error("Bad exclude parameter. Usage: --exclude-paths /path/to/exlude/1, /path/to/exlude/2, "
                            "/path/to/exlude/3...")
            exit()

    ex_words = ""
    if args.exclude_words:
        try:
            ex_words = args.exclude_words.strip(" ").split(",")
        except:
            my_parser.error("Bad exclude parameter. Usage: --exclude word1, word2, word3...")
            exit()

    if args.language == "rust":
        extension = "rs"
        vulns = read_vulns("./Rust/vuln_definition.conf")
        cargo_checks = read_cargo_checks("./Rust/cargo_checks.conf")
        cargo_findings = check_cargo_files(get_cargo_files_info(args.path, ex_paths), cargo_checks)

    else:
        extension = "sol"
        vulns = read_vulns("./Solidity/vuln_definition.conf")

    filepaths = get_files_info(args.path, extension, ex_paths)
    findings = find_everything(vulns, filepaths, ex_words, extension)

    interface = Interface()

    print_findings(findings, len(filepaths), args.ofile, args.simplified, interface)

    if args.language == "rust":
        print_cargo_findings(cargo_findings, interface)
