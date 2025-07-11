---
description: Docs A dictionary is a data set of key-value pairs.
---

# Dictionaries

Creata an empy dictionary

```python
empty_dict = {}
```

### Adding a key

We can add a key to the dictionary using `dictionary[key] = value`

```python
animals_in_zoo = {}

animals_in_zoo["zebras"] = 8
animals_in_zoo["monkeys"] = 12
animals_in_zoo["dinosaurs"] = 0

print(animals_in_zoo)
```

***

### Adding multiple keys

We can add multitple keys with `update()`

{% code overflow="wrap" %}
```python
user_ids = {"teraCoder": 9018293, "proProgrammer": 119238}
user_ids.update({"theLooper": 138475, "stringQueen": 85739})

print(user_ids)

# will print
{'teraCoder': 9018293, 'proProgrammer': 119238, 'theLooper': 138475, 'stringQueen': 85739}
```
{% endcode %}

***

### Overwriting values

Overwriting values can be with `menu["banana"] = 3`

```python
oscar_winners = {"Best Picture": "La La Land", "Best Actor": "Casey Affleck", "Best Actress": "Emma Stone", "Animated Feature": "Zootopia"}

oscar_winners["Supporting Actress"] = "Viola Davis"
oscar_winners["Best Picture"] = "Moonlight"
```

***

### Combining 2 lists into a dictionary

If we want to combine 2 lists into a dictionary we can use `zip` which combines two lists into an operator of tuples.

```python
names = ['James', 'Sarah', 'Sam', 'Grace']
heights = [55, 70, 67, 64]

students = {key:value for key, value in zip(names, heights)}
#students is now {'James': 55, 'Sarah': 70, 'Sam': 67, 'Grace': 64}
```

<details>

<summary>Another example</summary>

```python
drinks = ["espresso", "chai", "decaf", "drip"]
caffeine = [64, 40, 0, 120]

zipped_drinks = zip(drinks, caffeine)
drinks_to_caffeine = {key:value for key, value in zipped_drinks}

print(drinks_to_caffeine)
```

</details>

***

### Practice

{% code overflow="wrap" %}
```python
songs = ["Like a Rolling Stone", "Satisfaction", "Imagine", "What's Going On", "Respect", "Good Vibrations"]
playcounts = [78, 29, 44, 21, 89, 5]

# Creating a dictionary plays that goes trough songs and playcounts
plays = {key:value for key, value in zip(songs, playcounts)}
print(plays)

# Update and add new pair
plays["Purple Haze"] = 1
plays["Respect"] = 94

# Dictionary with 2 key value pairs
library = {"The Best Songs": plays, "Sunday Feelings": {}}

print(library)
```
{% endcode %}

***

### Get values

The get method in dictionaries is used to search for a value.

{% code overflow="wrap" %}
```python
user_ids = {"teraCoder": 100019, "pythonGuy": 182921, "samTheJavaMaam": 123112, "lyleLoop": 102931, "keysmithKeith": 129384}

# Prints 100019
tc_id = user_ids.get("teraCoder", 10000)

# Prints 100000 cause key doesnt exist
stack_id = user_ids.get("superStackSMash", 100000)
```
{% endcode %}

***

### Deleting a key using `pop`

Using pop we can remove keys from the dictionary. Here we add the value of the removed item ot health\_points.

```python
available_items = {"health potion": 10, "cake of the cure": 5, "green elixir": 20, "strength sandwich": 25, "stamina grains": 15, "power stew": 30}
health_points = 20

health_points += available_items.pop("stamina grains", 0)
health_points += available_items.pop("power stew", 0)
health_points += available_items.pop("mystic bread", 0)

# this will print
{'health potion': 10, 'cake of the cure': 5, 'green elixir': 20, 'strength sandwich': 25}
65
```

***

## Get all keys

To get all keys from a dictionary we can use:

{% code overflow="wrap" %}
```python
user_ids = {"teraCoder": 100019, "pythonGuy": 182921, "samTheJavaMaam": 123112, "lyleLoop": 102931, "keysmithKeith": 129384}

users = user_ids.keys()

# will print
dict_keys(['teraCoder', 'pythonGuy', 'samTheJavaMaam', 'lyleLoop', 'keysmithKeith'])

for users in user_ids.keys():
  print(users)
  
# will print
teraCoder
pythonGuy
samTheJavaMaam
lyleLoop
keysmithKeith
```
{% endcode %}

***

### Get all values

Besides getting all keys its also possible to get all values using `for score_list in test_scores.values():`

{% code overflow="wrap" %}
```python
num_exercises = {"functions": 10, "syntax": 13, "control flow": 15, "loops": 22, "lists": 19, "classes": 18, "dictionaries": 18}

total_exercises = 0

for num in num_exercises.values():
  total_exercises += num
  
# will print
115
```
{% endcode %}

***

### Get all items

You can get both keys and the values with the `.items()` method. Each element of the `dict_list` returned by `.items()` is a tuple consisting of (key, value)

{% code overflow="wrap" %}
```python
pct_women_in_occupation = {"CEO": 28, "Engineering Manager": 9, "Pharmacist": 58, "Physician": 40, "Lawyer": 37, "Aerospace Engineer": 9}

for job, percent in pct_women_in_occupation.items():
  print("Woman make up " + str(percent) + " percent of " + job + "s")
  
# will print
Woman make up 28 percent of CEOs
Woman make up 9 percent of Engineering Managers
Woman make up 58 percent of Pharmacists
Woman make up 40 percent of Physicians
Woman make up 37 percent of Lawyers
Woman make up 9 percent of Aerospace Engineers
```
{% endcode %}

***

### More practice

{% code overflow="wrap" %}
```python
tarot = { 1:	"The Magician", 2:	"The High Priestess", 3:	"The Empress", 4:	"The Emperor", 5:	"The Hierophant", 6:	"The Lovers", 7:	"The Chariot", 8:	"Strength", 9:	"The Hermit", 10:	"Wheel of Fortune", 11:	"Justice", 12:	"The Hanged Man", 13:	"Death", 14:	"Temperance", 15:	"The Devil", 16:	"The Tower", 17:	"The Star", 18:	"The Moon", 19:	"The Sun", 20:	"Judgement", 21:	"The World", 22: "The Fool"}

# Created empty dictionary
spread = {}

# Delete key 13 and assign "past" key to spread
spread["past"] = tarot.pop(13)

# Delete key 22 and assign "present" key to spread
spread["present"] = tarot.pop(22)

# Delete key 10 and assign "future" key to spread
spread["future"] = tarot.pop(10)

for key, value in spread.items():
  print("Your " + str(key) + " is the " + value + " card.")
```
{% endcode %}

{% content-ref url="../random-exercises/scrabble.md" %}
[scrabble.md](../random-exercises/scrabble.md)
{% endcontent-ref %}
