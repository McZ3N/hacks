---
description: Codecademy python working with strings
---

# Strings

## Thread Shed

<details>

<summary>the blob of text</summary>

{% code overflow="wrap" %}
````python
```codecademy-python
daily_sales = \
"""Edith Mcbride   ;,;$1.21   ;,;   white ;,; 
09/15/17   ,Herbert Tran   ;,;   $7.29;,; 
white&blue;,;   09/15/17 ,Paul Clarke ;,;$12.52 
;,;   white&blue ;,; 09/15/17 ,Lucille Caldwell   
;,;   $5.13   ;,; white   ;,; 09/15/17,
Eduardo George   ;,;$20.39;,; white&yellow 
;,;09/15/17   ,   Danny Mclaughlin;,;$30.82;,;   
purple ;,;09/15/17 ,Stacy Vargas;,; $1.85   ;,; 
purple&yellow ;,;09/15/17,   Shaun Brock;,; 
$17.98;,;purple&yellow ;,; 09/15/17 , 
Erick Harper ;,;$17.41;,; blue ;,; 09/15/17, 
Michelle Howell ;,;$28.59;,; blue;,;   09/15/17   , 
Carroll Boyd;,; $14.51;,;   purple&blue   ;,;   
09/15/17   , Teresa Carter   ;,; $19.64 ;,; 
white;,;09/15/17   ,   Jacob Kennedy ;,; $11.40   
;,; white&red   ;,; 09/15/17, Craig Chambers;,; 
$8.79 ;,; white&blue&red   ;,;09/15/17   , Peggy Bell;,; $8.65 ;,;blue   ;,; 09/15/17,   Kenneth Cunningham ;,;   $10.53;,;   green&blue   ;,; 
09/15/17   ,   Marvin Morgan;,;   $16.49;,; 
green&blue&red   ;,;   09/15/17 ,Marjorie Russell 
;,; $6.55 ;,;   green&blue&red;,;   09/15/17 ,
Israel Cummings;,;   $11.86   ;,;black;,;  
09/15/17,   June Doyle   ;,;   $22.29 ;,;  
black&yellow ;,;09/15/17 , Jaime Buchanan   ;,;   
$8.35;,;   white&black&yellow   ;,;   09/15/17,   
Rhonda Farmer;,;$2.91 ;,;   white&black&yellow   
;,;09/15/17, Darren Mckenzie ;,;$22.94;,;green 
;,;09/15/17,Rufus Malone;,;$4.70   ;,; green&yellow 
;,; 09/15/17   ,Hubert Miles;,;   $3.59   
;,;green&yellow&blue;,;   09/15/17   , Joseph Bridges  ;,;$5.66   ;,; green&yellow&purple&blue 
;,;   09/15/17 , Sergio Murphy   ;,;$17.51   ;,;   
black   ;,;   09/15/17 , Audrey Ferguson ;,; 
$5.54;,;black&blue   ;,;09/15/17 ,Edna Williams ;,; 
$17.13;,; black&blue;,;   09/15/17,   Randy Fleming;,;   $21.13 ;,;black ;,;09/15/17 ,Elisa Hart;,; $0.35   ;,; black&purple;,;   09/15/17   ,
Ernesto Hunt ;,; $13.91   ;,;   black&purple ;,;   
09/15/17,   Shannon Chavez   ;,;$19.26   ;,; 
yellow;,; 09/15/17   , Sammy Cain;,; $5.45;,;   
yellow&red ;,;09/15/17 ,   Steven Reeves ;,;$5.50   
;,;   yellow;,;   09/15/17, Ruben Jones   ;,; 
$14.56 ;,;   yellow&blue;,;09/15/17 , Essie Hansen;,;   $7.33   ;,;   yellow&blue&red
;,; 09/15/17   ,   Rene Hardy   ;,; $20.22   ;,; 
black ;,;   09/15/17 ,   Lucy Snyder   ;,; $8.67   
;,;black&red  ;,; 09/15/17 ,Dallas Obrien ;,;   
$8.31;,;   black&red ;,;   09/15/17,   Stacey Payne 
;,;   $15.70   ;,;   white&black&red ;,;09/15/17   
,   Tanya Cox   ;,;   $6.74   ;,;yellow   ;,; 
09/15/17 , Melody Moran ;,;   $30.84   
;,;yellow&black;,;   09/15/17 , Louise Becker   ;,; 
$12.31 ;,; green&yellow&black;,;   09/15/17 ,
Ryan Webster;,;$2.94 ;,; yellow ;,; 09/15/17 
,Justin Blake ;,; $22.46   ;,;white&yellow ;,;   
09/15/17,   Beverly Baldwin ;,;   $6.60;,;   
white&yellow&black ;,;09/15/17   ,   Dale Brady   
;,;   $6.27 ;,; yellow   ;,;09/15/17 ,Guadalupe Potter ;,;$21.12   ;,; yellow;,; 09/15/17   , 
Desiree Butler ;,;$2.10   ;,;white;,; 09/15/17  
,Sonja Barnett ;,; $14.22 ;,;white&black;,;   
09/15/17, Angelica Garza;,;$11.60;,;white&black   
;,;   09/15/17   ,   Jamie Welch   ;,; $25.27   ;,; 
white&black&red ;,;09/15/17   ,   Rex Hudson   
;,;$8.26;,;   purple;,; 09/15/17 ,   Nadine Gibbs 
;,;   $30.80 ;,;   purple&yellow   ;,; 09/15/17   , 
Hannah Pratt;,;   $22.61   ;,;   purple&yellow   
;,;09/15/17,Gayle Richards;,;$22.19 ;,; 
green&purple&yellow ;,;09/15/17   ,Stanley Holland 
;,; $7.47   ;,; red ;,; 09/15/17 , Anna Dean;,;$5.49 ;,; yellow&red ;,;   09/15/17   ,
Terrance Saunders ;,;   $23.70  ;,;green&yellow&red 
;,; 09/15/17 ,   Brandi Zimmerman ;,; $26.66 ;,; 
red   ;,;09/15/17 ,Guadalupe Freeman ;,; $25.95;,; 
green&red ;,;   09/15/17   ,Irving Patterson 
;,;$19.55 ;,; green&white&red ;,;   09/15/17 ,Karl Ross;,;   $15.68;,;   white ;,;   09/15/17 , Brandy Cortez ;,;$23.57;,;   white&red   ;,;09/15/17, 
Mamie Riley   ;,;$29.32;,; purple;,;09/15/17 ,Mike Thornton   ;,; $26.44 ;,;   purple   ;,; 09/15/17, 
Jamie Vaughn   ;,; $17.24;,;green ;,; 09/15/17   , 
Noah Day ;,;   $8.49   ;,;green   ;,;09/15/17   
,Josephine Keller ;,;$13.10 ;,;green;,;   09/15/17 ,   Tracey Wolfe;,;$20.39 ;,; red   ;,; 09/15/17 ,
Ignacio Parks;,;$14.70   ;,; white&red ;,;09/15/17 
, Beatrice Newman ;,;$22.45   ;,;white&purple&red 
;,;   09/15/17, Andre Norris   ;,;   $28.46   ;,;   
red;,;   09/15/17 ,   Albert Lewis ;,; $23.89;,;   
black&red;,; 09/15/17,   Javier Bailey   ;,;   
$24.49   ;,; black&red ;,; 09/15/17   , Everett Lyons ;,;$1.81;,;   black&red ;,; 09/15/17 ,   
Abraham Maxwell;,; $6.81   ;,;green;,;   09/15/17   
,   Traci Craig ;,;$0.65;,; green&yellow;,; 
09/15/17 , Jeffrey Jenkins   ;,;$26.45;,; 
green&yellow&blue   ;,;   09/15/17,   Merle Wilson 
;,;   $7.69 ;,; purple;,; 09/15/17,Janis Franklin   
;,;$8.74   ;,; purple&black   ;,;09/15/17 ,  
Leonard Guerrero ;,;   $1.86   ;,;yellow  
;,;09/15/17,Lana Sanchez;,;$14.75   ;,; yellow;,;   
09/15/17   ,Donna Ball ;,; $28.10  ;,; 
yellow&blue;,;   09/15/17   , Terrell Barber   ;,; 
$9.91   ;,; green ;,;09/15/17   ,Jody Flores;,; 
$16.34 ;,; green ;,;   09/15/17,   Daryl Herrera 
;,;$27.57;,; white;,;   09/15/17   , Miguel Mcguire;,;$5.25;,; white&blue   ;,;   09/15/17 ,   
Rogelio Gonzalez;,; $9.51;,;   white&black&blue   
;,;   09/15/17   ,   Lora Hammond ;,;$20.56 ;,; 
green;,;   09/15/17,Owen Ward;,; $21.64   ;,;   
green&yellow;,;09/15/17,Malcolm Morales ;,;   
$24.99   ;,;   green&yellow&black;,; 09/15/17 ,   
Eric Mcdaniel ;,;$29.70;,; green ;,; 09/15/17 
,Madeline Estrada;,;   $15.52;,;green;,;   09/15/17 
, Leticia Manning;,;$15.70 ;,; green&purple;,; 
09/15/17 ,   Mario Wallace ;,; $12.36 ;,;green ;,; 
09/15/17,Lewis Glover;,;   $13.66   ;,;   
green&white;,;09/15/17,   Gail Phelps   ;,;$30.52   
;,; green&white&blue   ;,; 09/15/17 , Myrtle Morris 
;,;   $22.66   ;,; green&white&blue;,;09/15/17"""
```
````
{% endcode %}

</details>

I got a blob of text shown here above. I'll use this snippet instead of the entire blob.

{% code overflow="wrap" %}
```python
daily_sales = \ 
"""Edith Mcbride   ;,;$1.21   ;,;   white ;,; 
09/15/17   ,Herbert Tran   ;,;   $7.29;,; 
white&blue;,;   09/15/17 ,Paul Clarke ;,;$12.52 
;,;   white&blue ;,; 09/15/17"""
```
{% endcode %}

### 1. Replace

First step, replace `;,;` for `+` using `string.replace(old, new)`

{% code overflow="wrap" %}
```python
daily_sales_replaced = daily_sales.replace(";,;", "+")
```
{% endcode %}

{% code overflow="wrap" %}
```
Edith Mcbride   +$1.21   +   white + 
09/15/17   ,Herbert Tran   +   $7.29+ 
white&blue+   09/15/17 ,Paul Clarke +$12.52 
+   white&blue + 09/15/17
```
{% endcode %}

### 2. Split

Then we split the strings at the `,` into a list using `string.split(delimiter)`

{% code overflow="wrap" %}
```python
daily_transactions = daily_sales_replaced.split(",")
```
{% endcode %}

{% code overflow="wrap" %}
```
['Edith Mcbride   +$1.21   +   white + \n09/15/17   ', 'Herbert Tran   +   $7.29+ \nwhite&blue+   09/15/17 ', 'Paul Clarke +$12.52 \n+   white&blue + 09/15/17']
```
{% endcode %}

### 3. Split attributes

Now split attributes of each transaction and remove the `+` from step 1

{% code overflow="wrap" %}
```python
# create empty list
daily_transactions_split = []

# Iterate, append and split a transaction. 
for transaction in daily_transactions:
    daily_transactions_split.append(transaction.split("+"))
```
{% endcode %}

{% code overflow="wrap" %}
```
[['Edith Mcbride   ', '$1.21   ', '   white ', ' \n09/15/17   '], ['Herbert Tran   ', '   $7.29', ' \nwhite&blue', '   09/15/17 '], ['Paul Clarke ', '$12.52 \n', '   white&blue ', ' 09/15/17']]
```
{% endcode %}

### 4. Replace and strip

Using 2 for loops replace the `\n` for a `""` and `strip` whitespaces. First loop iterates over daily\_transactions\_split. The second for loop is iterating over the individual datapoints as we're not cleaning transactions.

{% code overflow="wrap" %}
```python
# Empty list
transactions_clean = []

for transaction in daily_transactions_split:
  trans_clean = []
  for item in transaction:
    trans_clean.append(item.replace("\n", "").strip())
  transactions_clean.append(trans_clean)
```
{% endcode %}

Now it starting to look clean

{% code overflow="wrap" %}
```
[['Edith Mcbride', '$1.21', 'white', '09/15/17'], ['Herbert Tran', '$7.29', 'white&blue', '09/15/17'], ['Paul Clarke', '$12.52', 'white&blue', '09/15/17']]
[['Edith Mcbride', '$1.21', 'white', '09/15/17'], ['Herbert Tran', '$7.29', 'white&blue', '09/15/17'], ['Paul Clarke', '$12.52', 'white&blue', '09/15/17']]
```
{% endcode %}

### 5. Arrange data in lists

{% code overflow="wrap" %}
```python
# Create lists
customers = []
sales = []
thread_sold = []

# First item in transaction goes to index[0] and so on.
for transaction in transactions_clean:
  customers.append(transaction[0])
  sales.append(transaction[1])
  thread_sold.append(transaction[2])
```
{% endcode %}

{% code overflow="wrap" %}
```
['Edith Mcbride', 'Herbert Tran', 'Paul Clarke']
['$1.21', '$7.29', '$12.52']
['white', 'white&blue', 'white&blue']
```
{% endcode %}

### 6. Calculate total sales

Converting string to number using `float` and strip to remove the `$`

{% code overflow="wrap" %}
```python
total_sales = 0
for sale in sales:
  total_sales += float(sale.strip("$"))  
```
{% endcode %}

{% code overflow="wrap" %}
```
21.02
```
{% endcode %}

### 7. Remove multiple colors

Using `split` we remove the `&` and `append` it in new list

{% code overflow="wrap" %}
```python
thread_sold_split = []
for sale in thread_sold:
  for color in sale.split("&"):
    thread_sold_split.append(color)
```
{% endcode %}

{% code overflow="wrap" %}
```
['white', 'white', 'blue', 'white', 'blue']
```
{% endcode %}

### 8. Create function

Make function to count the number of colors.&#x20;

{% code overflow="wrap" %}
```python
# It checks colors in thread_sold_split and if machtes input like "white" it will add 1 to total color. 
def color_count(color):
  total_color = 0
  for thread_color in thread_sold_split:
    if color == thread_color:
      total_color += 1
  return total_color

# Count color white
print(color_count("white"))

# Will result in:
3
```
{% endcode %}

### 9. Print using format

Printing a string showing how many threads sold using `format`.&#x20;

{% code overflow="wrap" %}
```python
# list with colors
colors = ['red', 'yellow', 'green', 'white', 'black', 'blue', 'purple']

# loop which uses function with format to print amount and color, at {0} and {1}
for color in colors:
  print("There were {0} {1} threads sold today.".format(color_count(color), color))
```
{% endcode %}

{% code overflow="wrap" %}
```
There were 0 red threads sold today.
There were 0 yellow threads sold today.
There were 0 green threads sold today.
There were 3 white threads sold today.
There were 0 black threads sold today.
There were 2 blue threads sold today.
There were 0 purple threads sold today.
```
{% endcode %}

