---
description: For codecademy doing the caecar's encrytion
---

# Caesar's encryption

Caesar's encryption is a simple substitution cipher where each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. For example, with a shift of 3, A would be replaced by D, B would be replaced by E, and so on.

<figure><img src="broken-reference" alt=""><figcaption><p>Here we decode and encode shifting with 10</p></figcaption></figure>

### The script

Simply by changing to `+` or `-` in the line `shifted_number = (number - offset) % 26` will swtich between encoding and decoding.

{% code overflow="wrap" %}
```python
# Ask for message and offset
input_message = input('Write message: ')

# Encode/Decode 
def caesar_decode(input_message, offset):
    result = ''
    characters = list(input_message.lower())

    # Convert chars to ASII 
    for character in characters:
        if character in ".,?'! ":
            result += character

        elif character.isalpha():
            
            # Convert to number
            number = ord(character.lower()) - 97

            # Calculate the shift - for encode + for decode
            shifted_number = (number - offset) % 26

            # Convert back to char
            shifted_char = chr(shifted_number + 97)
            result += shifted_char
        
        else:
            result += character

    return result 

# bruteforce the shift
for offset in range(26):
    decoded_message = caesar_decode(input_message, offset)

    # Print result
    print(f"Shift {offset}: {decoded_message}")
```
{% endcode %}

{% hint style="info" %}
The `ord()` turns the character into ASCI value so `'d'` becomes `100`. So subtracting `97` gives a value of `3`. We can then shift by 10, `3 - 10` which is `-7` . We then use modulo to `-7 % 26 = 19`. Finally we add `19 + 97` to get the ASCI char again.
{% endhint %}
