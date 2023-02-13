"""
Author: Samuel Hríbik
Login: xhribi00
About: This is an implementation of a password mask generator proposed in my bachelor thesis.
"""

import argparse
import string

class PasswordAnalyzer:
    '''Takes given arguments, filters and analyzes compatible passwords.'''
    def __init__(self, arg_options):
        self.minlength = arg_options.minlength
        self.minlower = arg_options.minlower
        self.minupper = arg_options.minupper
        self.mindigit = arg_options.mindigit
        self.minspecial = arg_options.minspecial
        self.maxlength = arg_options.maxlength
        self.maxlower = arg_options.maxlower
        self.maxupper = arg_options.maxupper
        self.maxdigit = arg_options.maxdigit
        self.maxspecial = arg_options.maxspecial
        self.wordlists = arg_options.wordlists
        self.masks = {}

    def analyze(self):
        '''Iterate through passwords in wordlists and analyze passwords compatible with policy.'''

        for filename in self.wordlists:
            try:
                with open(filename, 'r', encoding="latin-1") as file:
                    for password in file:

                        password = password.rstrip('\r\n')

                        upper = 0
                        lower = 0
                        digits = 0
                        special = 0
                        mask = ""

                        for letter in password:
                            if letter in string.ascii_lowercase:
                                lower += 1
                                mask += "?l"
                            elif letter in string.ascii_uppercase:
                                upper += 1
                                mask += "?u"
                            elif letter in string.digits:
                                digits += 1
                                mask += "?d"
                            else:
                                special += 1
                                mask += "?s"

                        if (not self.minlength <= len(password) <= self.maxlength
                            or not self.minlower <= lower <= self.maxlower
                            or not self.minupper <= upper <= self.maxupper
                            or not self.mindigit <= digits <= self.maxdigit
                            or not self.minspecial <= special <= self.maxspecial):
                            continue


                        if mask in self.masks:
                            self.masks[mask] += 1
                        else:
                            self.masks[mask] = 1

            except OSError:
                pass

        sorted_by_occurrence = dict(sorted(self.masks.items(), key=lambda x:x[1], reverse=True))
        for key in sorted_by_occurrence:
            if sorted_by_occurrence[key] >= options.minocc:
                print(key + ", " + str(sorted_by_occurrence[key]))


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("--minlength", dest="minlength", type=int,
                        default=0, help="Minimum password length")
    parser.add_argument("--maxlength", dest="maxlength", type=int,
                        default=9999, help="Maximum password length")
    parser.add_argument("--minlower", dest="minlower", type=int,
                        default=0, help="Minimum number of lowercase characters")
    parser.add_argument("--maxlower", dest="maxlower", type=int,
                        default=9999, help="Maximum number of lowercase characters")
    parser.add_argument("--minupper", dest="minupper", type=int,
                        default=0, help="Minimum number of uppercase characters")
    parser.add_argument("--maxupper", dest="maxupper", type=int,
                        default=9999, help="Maximum number of uppercase characters")
    parser.add_argument("--mindigit", dest="mindigit", type=int,
                        default=0, help="Minimum number of digits")
    parser.add_argument("--maxdigit", dest="maxdigit", type=int,
                        default=9999, help="Maximum number of digits")
    parser.add_argument("--minspecial", dest="minspecial", type=int,
                        default=0, help="Minimum number of special characters")
    parser.add_argument("--maxspecial", dest="maxspecial", type=int,
                        default=9999, help="Maximum number of special characters")
    parser.add_argument("--minocc", dest="minocc", type=int,
                        default=0, help="Minimum number of occurences of a mask")
    parser.add_argument("-w", "--wordlists", dest="wordlists", action="append",
                        help="Wordlists for analysis")

    options = parser.parse_args()

    if options.wordlists is not None:
        analyzer = PasswordAnalyzer(options)
        analyzer.analyze()

    else:
        print("No wordlists")
