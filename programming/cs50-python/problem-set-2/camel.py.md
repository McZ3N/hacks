# camel.py

```python
# Prompt user for name of a variable
variable_name = input("camelCase: ")

# Check for char if upper than conver to lower
chars = []
for i in variable_name:
    if i.isupper():
        chars.append("_" + i.lower())
    else:
        chars.append(i)

# Join chars together.
delimiter = ""
join_str = delimiter.join(chars)
print("snake_case: " + join_str)
```
