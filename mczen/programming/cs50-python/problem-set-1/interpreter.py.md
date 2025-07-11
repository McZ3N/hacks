# interpreter.py

```python
# Prompt user for arithmetic expression
x, y, z = input("Expression: ").split(" ")

# Calculate the expression
if y == "+":
    output = float(x) + float(z)
elif y == "-":
    output = float(x) - float(z)
elif y == "*":
    output = float(x) * float(z)
else:
    output = float(x) / float(z)

print(output)
```
