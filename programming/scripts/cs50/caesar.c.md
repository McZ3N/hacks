---
description: Harvard CS50 - Problem Set 2
---

# caesar.c

```c
/#include <cs50.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, string argv[])
{
    // check arguments
    if (argc != 2)
    {
        printf("Usage: ./caesar key\n");
        return 1;
    }
    
    // shift
    int k = atoi(argv[1]);

    // get user input and check for alphabeticals
    string str = get_string("Plain: ");
    {
        for (int i = 0; str[i] != '\0'; i++)

            if (!isalpha(str[i]))
            {
                printf("Input must only contain letters (a-z or A-Z).\n");
                return 1;
            }
    }
    
    // cipher
    printf("Ciphertext: ");
    for (int i = 0, n = strlen(str); i < n; i++)
        if (islower(str[i]))
        {
            printf("%c", ((str[i] - 'a' + k) % 26) + 'a');
        }
        else
        {
            printf("%c", ((str[i] - 'A' + k) % 26) + 'A');
        }
    printf("\n");
}
```
