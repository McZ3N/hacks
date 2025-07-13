---
description: This program calculates times base on year difference * a multiplier.
---

# Time travel calculator

{% code overflow="wrap" %}
```python
from datetime import datetime as dt
from decimal import Decimal
from random import randint, choice
from custom_module import generate_time_travel_message

# Needs to be a string
base_cost = Decimal("5000")

# Current year
current_year = dt.today().year
target_year = randint(2025, 2125)

# Calculate difference
cost_multiplier = abs(current_year - target_year)

# Combine cost with year difference
travel_cost = base_cost * cost_multiplier

# Destinations
destination = ["Amsterdam", "London", "Paris", "Berlin", "Madrid"]

# Print random destitnation and year with cost
print(generate_time_travel_message(target_year, choice(destination), travel_cost))
```
{% endcode %}

#### Datetime module

`current_year = datetime.today().year` can be used to call the current year like 2024. Where `datetime.now().time()`  08:29:13.629542.\
\
[https://docs.python.org/3/library/datetime.html](https://docs.python.org/3/library/datetime.html)



Random module

Using from random import randint, choice its possible to select an random integer and choosing a random item within a list.

* `target_year = randint(2025, 2125)`
* `choice(destination)` or  `random.choice(destination)`
