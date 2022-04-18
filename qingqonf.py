#!/usr/bin/python3
import getpass

##################################################
#
#   Environment variables used by qingqualys
#     functions.
#   See https://www.qualys.com/platform-identification/
#     to determine hostname
#
##################################################


base_url = 'qualysguard.qg4.apps.qualys.com'
username = getpass.getpass("Username: ")
password = getpass.getpass("Password: ")
