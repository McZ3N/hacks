# twttr.py

```python
# Prompt user for a string
str_input = input("Input: ")
vowels = ["a", "e", "i", "o", "u","A", "E", "I", "O", "U"]
new_word = ""

for char in str_input:
    if char not in vowels:
        new_word += char

print(new_word)
```
