# tip.py

```python
def main():
    dollars = dollars_to_float(input("How much was the meal? "))
    percent = percent_to_float(input("What percentage would you like to tip? "))
    tip = dollars * percent
    print(f"Leave ${tip:.2f}")

# Accept str as input as $##.##, removing leading $, return amount as float.
def dollars_to_float(d):
    s = d.lstrip(d[0])
    return float(s)

# Accept str as in put ##%, removing %, convert to float / 100.
def percent_to_float(p):
    s = p.rstrip(p[-1])
    return float(s) / 100

main()
```
