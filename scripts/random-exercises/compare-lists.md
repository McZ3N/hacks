---
description: Compare numbers in a list and return common.
---

# Compare lists

{% hint style="info" %}
Several ways to do this, like this oneliner:\
`common = list(set(random.sample(range(1, 50), 10)) & set(random.sample(range(1, 50), 10)))`
{% endhint %}

### sets

A very effective way to compare items in a list is using `common = list(set(a) & set(b))`.

{% code overflow="wrap" %}
```python
# Using sets
a = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]
b = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

common = list(set(a) & set(b))
print("This is using sets: ", common)

# will print
This is using sets:  [1, 2, 3, 5, 8, 13]
```
{% endcode %}

### randint

Use to generate using `list.append(random.randint(1,20))`

```python
# Generate random lists
import random

rand_list_a = []
rand_list_b = []

# 20 random digits under 30
for i in range(1, 20):
    rand_list_a.append(random.randint(1,30))
    rand_list_b.append(random.randint(1,30))

# Using sets again to compare
commons = list(set(rand_list_a) & set(rand_list_b))

print("\nThis is using random list generation", commons)

# will print
This is using random list generation [3, 4, 5, 10, 11, 12, 17, 18, 19, 21]
```

### random.sample

```python
# Generate random list method 2.
c = random.sample(range(1, 50), 10)
d = random.sample(range(1, 50), 10)

incommon = []
for num in c:
    if num in d:
        incommon.append(num)

print("\nThis is usin random.sample and if operater", incommon)
```

### oneliner

```python
common = list(set(random.sample(range(1, 50), 10)) & set(random.sample(range(1, 50), 10)))
print("Oneliner: ", common)

# will print
Oneliner:  [20, 6]
```



