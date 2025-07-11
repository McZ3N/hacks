---
description: A script calculating Scrabble scores using dictionaries.
---

# Scrabble

{% code overflow="wrap" %}
```python
letters = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
points = [1, 3, 3, 2, 1, 4, 2, 4, 1, 8, 5, 1, 3, 4, 1, 3, 10, 1, 1, 1, 1, 4, 4, 8, 4, 10]

# Create dictionary from 2 lists
letter_to_points = {key:value for key, value in zip(letters, points)}

# Add element
letter_to_points[" "] = 0

# Iterate over letters in word and .get value of letter
def score_word(word):
  point_total = 0
  for letter in word:
    point_total += letter_to_points.get(letter, 0)
  return point_total 

brownie_points = score_word("BROWNIE")
print(brownie_points)

# Part 2
player_to_words = {
  "player1": ["BLUE", "TENNIS", "EXIT"],
  "wordNerd": ["EARTH", "EYES", "MACHINE"],
  "Lexi Con": ["ERASER", "BELLY", "HUSKY"],
  "Prof Reader": ["ZAP", "COMA", "PERIOD"]
}

# Get keys/values wit items then get a word which uses score_word function to iterates letters and get score. And finally each overwrites the dictionary value with the score
player_to_points = {}
for player, words in player_to_words.items():
  player_points = 0
  for word in words:
    player_points += score_word(word)
  player_to_points[player] = player_points

print(player_to_points)

# It will print
15
{'player1': 29, 'wordNerd': 32, 'Lexi Con': 31, 'Prof Reader': 31}
```
{% endcode %}
