# faces.py

```python
# Return converted string with emojis
def convert(greeting):
    greeting = str(greeting.replace(":)", "🙂")).replace(":(", "🙁")
    return greeting

# Print convert function with input
def main():
    print(convert(input("")))

main()
```

