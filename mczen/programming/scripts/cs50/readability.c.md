---
description: Harvard CS50 - Problem Set 2
---

# readability.c

```c
#include <cs50.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>

int count_letters(string text);
int count_words(string text);
int count_sentences(string text);

int main(void)
{
    // prompt the user for some text
    string text = get_string("Input text: ");

    // compute the Coleman-Liau index
    float L = (float) count_letters(text) / (float) count_words(text) * 100;
    float S = (float) count_sentences(text) / (float) count_words(text) * 100;

    float result = 0.0588 * L - 0.296 * S - 15.8;
    int roundResult = round(result);

    // print results
    if (roundResult > 16)
    {
        printf("Grade 16+\n");
    }
    else if (roundResult < 1)
    {
        printf("Before Grade 1\n");
    }
    else
    {
        printf("Grade %i\n", roundResult);
    }
}

int count_letters(string text)
{
    // loop and count alphabeticals
    int letter = 0;
    for (int n = 0; text[n] != '\0'; n++)

        if (isalpha(text[n]))
        {
            letter++;
        }
    return letter;
}

int count_words(string text)
{
    // loop and count spaces
    int words = 1;
    for (int n = 0; text[n] != '\0'; n++)

        if (isspace(text[n]))
        {
            words++;
        }
    return words;
}

int count_sentences(string text)
{
    // loop and count sentences
    int s = 0;
    for (int n = 0; text[n] != '\0'; n++)

        if (text[n] == '.' || text[n] == '!' || text[n] == '?')
        {
            s++;
        }
    return s;
}
```
