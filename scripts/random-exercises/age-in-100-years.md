---
description: Tells the year it is when they will turn 100 years old
---

# Age in 100 years

{% code overflow="wrap" %}
```python
import sys
import datetime

# Arguments check.
if len(sys.argv) != 3: 
    print("Usage: file.py name age")
    sys.exit()
else:
    name = sys.argv[1]
    age = int(sys.argv[2])

# Uses datetime for year - age + 100. 
print(f"Hi {name} you will be 100 in the year {str(datetime.datetime.today().year - age + 100)}")
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>
