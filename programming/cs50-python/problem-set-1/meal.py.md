# meal.py

```python
# Check what time for meal
def main():
    time = input("What time is it? ")
    meal = convert(time)

    if 7 <= meal <= 8:  # Breakfast time
        print("breakfast time")
    elif 12 <= meal <= 13:  # Lunch time
        print("lunch time")
    elif 18 <= meal <= 19:  # Dinner time
        print("dinner time")

# Convert time to decimal
def convert(time):
    hours, minutes = time.split(":")
    return float(hours) + float(minutes) / 60

if __name__ == "__main__":
    main()
```
