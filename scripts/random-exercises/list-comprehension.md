---
description: >-
  List comprehension offers a shorter syntax when you want to create a new list
  based on the values of an existing list.
---

# List comprehension

```python
a = [1, 4, 9, 16, 25, 36, 49, 64, 81, 100]

print([i for i in a if i % 2 == 0])

# will print
[4, 16, 36, 64, 100]
```

