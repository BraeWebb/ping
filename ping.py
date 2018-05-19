#!/usr/local/bin/python3

import argparse
import sys
from enum import Enum


class Errors(Enum):
    """An Enum representing the types of errors that may occur."""
    SOCKET_ERROR = "Unable to open TCP socket connection to {}"
    HOSTNAME_ERROR = "Hostname ({}) could not be resolved."


def log_error(error, *parameters):
    """
    Log that an error has occurred and exit the program.
    Args:
        error (Errors): The type of error that has occurred.
        *parameters (*): Any extra information relevant to the error.
    """
    print(error.name, ":", error.value.format(*parameters))
    sys.exit(1)


def main():
    """Main programmy thing, y'all know what it do"""
    parser = argparse.ArgumentParser(description="Ping Tool")

    parser.add_argument("hostname", type=str, action="store",
                        help="the hostname to lookup")

    args = parser.parse_args()


if __name__ == "__main__":
    main()