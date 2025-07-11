---
description: Check for odd/even numbers using modulo.
---

# Check odd/even numbers

{% code overflow="wrap" %}
```python
import sys

if len(sys.argv) != 3:
    print("Usage: exercise.py number number_divide")
    sys.exit()

else:
    num = int(sys.argv[1])
    check = int(sys.argv[2])
    
    if num % 4 == 0:
        print("Youre number is a multiple of 4")
    elif num % 2 == 0:
        print("You're number is even")
    else:
        print("You're number is not even")

    if num % check == 0:
        print(num, "divides evenly by", check)
    else:
        print(num, "does not divide evenly by", check)
```
{% endcode %}

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
