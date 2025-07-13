# bank.py

```python
# Prompt user for greeting
greeting = input("Greeting: ").strip().lower()

# If greeting starts with "hello"
if greeting.startswith("hello"):
    print("$0")
elif greeting.startswith("h"):
    print("$20")
else:
    print("$100")
```

