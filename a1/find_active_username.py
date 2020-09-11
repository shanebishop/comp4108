# import selenium
from selenium import webdriver

driver = webdriver.Chrome()
print(driver)
x = driver.get('http://localhost:5000/login')
print(x)

login_field = driver.find_element_by_name('username')
print(login_field)
login_field.send_keys('my_username')

login_btn = driver.find_element_by_class_name('btn')
login_btn.click()
