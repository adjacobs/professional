"""

test_validation.py

Created by ajacobs

6/27/2022

Function:
 
"""
from validation.checker import CheckerError

def scan():
    """
    Checks for controllers with animation keys
    """
    # get list of controls
    error_list = []

    if error_list:
        raise CheckerError('Some controllers have animation keys.', error_list)


def info():
    return 'Testing validation.'


def repair(error_list):
    """
    Removes animation keys from controllers
    """
    for error in error_list:
        print('Fixing Error.')