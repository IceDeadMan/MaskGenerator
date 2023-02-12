"""
Author: Samuel Hríbik
Login: xhribi00
About: This is an implementation of a password mask generator proposed in my bachelor thesis.
"""

from optparse import OptionParser

if __name__ == "__main__":

    parser = OptionParser()

    parser.add_option("--minlength", dest="minlength", type="int", help="Minimum password length")
    parser.add_option("--maxlength", dest="maxlength", type="int", help="Maximum password length")
    parser.add_option("--minlower", dest="minlower", type="int", help="Minimum number of lowercase characters")
    parser.add_option("--maxlower", dest="maxlower", type="int", help="Maximum number of lowercase characters")
    parser.add_option("--minupper", dest="minupper", type="int", help="Minimum number of uppercase characters")
    parser.add_option("--maxupper", dest="maxupper", type="int", help="Maximum number of uppercase characters")
    parser.add_option("--mindigit", dest="mindigit", type="int", help="Minimum number of digits")
    parser.add_option("--maxdigit", dest="maxdigit", type="int", help="Maximum number of digits")
    parser.add_option("--minspecial", dest="minspecial", type="int", help="Minimum number of special characters")
    parser.add_option("--maxspecial", dest="maxspecial", type="int", help="Maximum number of special characters")

    (options, args) = parser.parse_args()

    print("oznuk")
