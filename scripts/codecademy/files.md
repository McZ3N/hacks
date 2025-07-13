---
description: Files are individual containers used to store data
---

# Files

#### Reading files

A file is opend by creating a file object where the content can be used by using `.read`

```python
with open('welcome.txt') as text_file:
  text_data = text_file.read()
  print(text_data)
```

#### Iterating through lines

We can use the `.readlines()` function to read a text file line by line instead of having the whole thing.

```python
with open('how_many_lines.txt') as lines_doc:
  for line in lines_doc.readlines():
    print(line)
```

#### Reading a line

Returns the first line of content from an open file.[`.readline()`](https://www.codecademy.com/resources/docs/python/files/readline?page_ref=catalog), which will only read a single line at a time.

```python
with open('just_the_first.txt') as first_line_doc:
  first_line = first_line_doc.readline()
print(first_line)
```

#### Writing a file

With the open function we can also write files using the `'w'` argument. We can write data to a file.

```python
# Abba is written to file here
with open('bad_bands.txt', 'w') as bad_bands_doc:
  bad_bands = bad_bands_doc.write("Abba")
```

#### Appending to a file.

We can open it with `'a'` for append-mode.

```python
with open('cool_dogs.txt', 'a') as cool_dogs_file:
  cool_dogs_file.write("Air Buddy\n")
```

{% hint style="info" %}
with

Using a `with` block when opening files in Python creates a context manager that automatically closes the file after the indented block ends, preventing potential issues with open file connections.

```python
# method without  with
fun_cities_file = open('fun_cities.txt', 'a')

# We can now append a line to "fun_cities".
fun_cities_file.write("Montréal")

# But we need to remember to close the file
fun_cities_file.close()
```


{% endhint %}

#### Reading a .csv file

We convert data from a csv file into a dictionary using the DictReader object.

```python
import csv

# opens file and print key 'Cool Fact' in each row.
with open('cool_csv.csv') as cool_csv_file:
  cool_csv_dict = csv.DictReader(cool_csv_file)
  for row in cool_csv_dict:
    print(row['Cool Fact'])
    
# Use @ as delimiter and get ISBN for every row
with open('books.csv') as books_csv:
  books_reader = csv.DictReader(books_csv, delimiter='@')
  isbn_list = []
  for book in books_reader:
    isbn_list.append(book['ISBN']) 
```

### Hacking the fender exercise

{% code overflow="wrap" %}
```python
import csv
import json

compromised_users = []

# Get usernams froms passwords.csv and append to commpromised users.
with open("passwords.csv") as password_file:
  password_csv = csv.DictReader(password_file)
  for password_row in password_csv:
    compromised_users.append(password_row['Username'])

# Write compromised users to compromised_user_file
with open('compromised_users.txt', 'w') as compromised_user_file:
  for compromised_user in compromised_users:
    compromised_user_file.write(compromised_user)

# Create dictionary boss message
with open('boss_message.json', 'w') as boss_message:
  boss_message_dict = {"recipient": "The Boss", "message": "Mission Success"}
  json.dump(boss_message_dict, boss_message)

# Write signatur to new_passwords.csv
with open('new_passwords.csv', 'w') as new_passwords_obj:
  slash_null_sig = """
   _  _     ___   __  ____             
/ )( \   / __) /  \(_  _)            
) \/ (  ( (_ \(  O ) )(              
\____/   \___/ \__/ (__)             
 _  _   __    ___  __ _  ____  ____  
/ )( \ / _\  / __)(  / )(  __)(    \ 
) __ (/    \( (__  )  (  ) _)  ) D ( 
\_)(_/\_/\_/ \___)(__\_)(____)(____/ 
        ____  __     __   ____  _  _ 
 ___   / ___)(  )   / _\ / ___)/ )( \
(___)  \___ \/ (_/\/    \\___ \) __ (
       (____/\____/\_/\_/(____/\_)(_/
 __ _  _  _  __    __                
(  ( \/ )( \(  )  (  )               
/    /) \/ (/ (_/\/ (_/\             
\_)__)\____/\____/\____/
"""
  new_passwords_obj.write(slash_null_sig)
```
{% endcode %}
