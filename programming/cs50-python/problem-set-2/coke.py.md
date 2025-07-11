# coke.py

```python
def main():
    amount_due = 50
    while amount_due > 0:
        print(f"Amount Due: {amount_due}")
        coins = int(input("Insert Coin: "))
        amount_due = calculate_change(amount_due, coins)


def calculate_change(amount_due, coins):
    if coins != 25 and coins != 10 and coins != 5:
        print(amount_due)
    else:
        amount_due -= coins

    # Change owned
    if amount_due <= 0:
        change = abs(amount_due)
        print(f"Change owed: {change}")
    return amount_due


main()
```
