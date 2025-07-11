---
description: Python equips us with many different ways to store data.
---

# Classes

### What is a class?

A class is a template for a data type or object. A class must be instantiated, we have to create in instance of the class becomes on object.

```python
class Character:

    # Attributes
    def __init__(self, health, damage, speed):
        self.health = health
        self.damage = damage
        self.speed = speed 

# Instance or object
warrior = Character(100, 50, 20)
ninja = Character(100, 40, 10)

# Print spreed attribute
print(warrior.speed)
print(ninja.damage)

# Prints
20
40
```

***

### Class variables

A class variable is a variable that’s the same for every instance of the class, which we use if we want the same data to be available to every instance.

```python
class Grade:
  minimum_passing = 65

passed = Grade()
print(passed.minimum_passing)
```

***

### Methods

Methods are like functions but are defined as part of a class, usually first argument is self. We define methods similarly to functions, except that they are indented to be part of the class.

<details>

<summary>Example</summary>

{% code overflow="wrap" %}
```python
class Dog:
  dog_time_dilation = 7

  def time_explanation(self):
    print("Dogs experience {} years for every 1 human year.".format(self.dog_time_dilation))

pipi_pitbull = Dog()
pipi_pitbull.time_explanation()
# Prints "Dogs experience 7 years for every 1 human year."
```
{% endcode %}

</details>

```python
class Rules:
  def washing_brushes(self):
    return "Point bristles towards the basin while washing your brushes."
```

***

### Methods with arguments

Methods can also take more arguments than just `self.` When using more arguments we only pass 1 in this example as `self` is implicitly passed

```python
# Class and variable pi
class Circle:
  pi = 3.14

# Area method with 2 parameters and return circle.pi
  def area(self, radius):
    return circle.pi * radius ** 2

# Instance of Circle saved in circle variable
circle = Circle()

pizza_area = circle.area(12 / 2)
teaching_table_area = circle.area(36 / 2)
round_room_area = circle.area(11460 / 2)
```

***

### Constructors

There are several methods that we can define in a Python class that have special behavior. These methods are sometimes called “magic,” because they behave differently from regular methods.

{% hint style="info" %}
Methods that are used to prepare an object being instantiated are called _constructors or "dunder methods"._
{% endhint %}

```python
class Circle:
  pi = 3.14
  
  # Constructor here.
  def __init__(self, diameter):
    self.diameter = diameter
    print(f"New circle with diameter: {diameter}")
  
teaching_table = Circle(36)

# will print
New circle with diameter: 36
```

***

### Instance variables

The data held by an object is referred to as an _instance variable_. Instance variables aren’t shared by all instances of a class — they are variables that are specific to the object they are attached to.

{% code overflow="wrap" %}
```python
class Store:
  pass

# Objects        
alternative_rocks = Store()
isabelles_ices = Store()

# Instance attributes
alternative_rocks.store_name = "Alternative Rocks"
isabelles_ices.store_name = "Isabelle's Ices"

# Print
print("This is {} and {}".format(alternative_rocks.store_name,  isabelles_ices.store_name))

# will print
This is Alternative Rocks and Isabelle's Ices
```
{% endcode %}

***

### Attribute functions

Instance [variables](https://www.codecademy.com/resources/docs/python/variables) and class variables are both accessed similarly in Python. They are both attributes of an object. If we attempt to access an attribute that is neither a class variable nor an instance variable of the object Python will throw an `AttributeError`.

This can be checked with `hasattr(attributeless, "fake_attribute")`

```python
can_we_count_it = [{'s': False}, "sassafrass", 18, ["a", "c", "s", "d", "s"]]

for element in can_we_count_it:
  if hasattr(element, "count" ):
    print(str(type(element)) + " has the count attribute!")
  else:
    print(str(type(element)) + " does not have the count attribute :(")
```

***

### Self

Instance variables are more powerful when you can guarantee a rigidity to the data the object is holding. This convenience is most apparent when the constructor creates the instance variables using the arguments passed into it.

{% code overflow="wrap" %}
```python
class Circle:
  pi = 3.14

  # Circles constructor
  def __init__(self, diameter):
    print("Creating circle with diameter {d}".format(d=diameter))
    # Add assignment for self.radius here:
    self.radius =  diameter / 2
  
  # New method which returns circumference for circle object
  def circumference(self):
    return 2 * self.pi * self.radius

# Circle objects
medium_pizza = Circle(12)
teaching_table = Circle(36)
round_room = Circle(11460)

print(medium_pizza.circumference())
print(teaching_table.circumference())
print(round_room.circumference())
```
{% endcode %}

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

***

### Everything is an object

We can use the `dir` function to investigate an object’s attributes at runtime. `dir()` is short for _directory_ and offers an organized presentation of object attributes.

{% code overflow="wrap" %}
```python
def this_function_is_an_object(test):
  return test
print(dir(this_function_is_an_object))
```
{% endcode %}

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

***

### String representation

We learned about the dunder method, a newly created object and is called each time a new class instance is created.[`__init__()`](https://www.codecademy.com/resources/docs/python/dunder-methods/init). Now, we will learn another dunder method called string representation of the class[`__repr__()`](https://www.codecademy.com/resources/docs/python/dunder-methods/repr?page_ref=catalog). This is a method we can use to tell Python what we want the _string representation_ of the class to be. `__repr__()` can only have one parameter, `self`, and must return a string.

{% code overflow="wrap" %}
```python
class Circle:
  # Class attribute
  pi = 3.14
  
  # Constructor
  def __init__(self, diameter):
    self.radius = diameter / 2

  # Area method  
  def area(self):
    return self.pi * self.radius ** 2
  
  # Circumference method
  def circumference(self):
    return self.pi * 2 * self.radius
  
  # Define how circle object is displayed
  def __repr__(self):
    return "Circle with radius {radius}".format(radius=self.radius)
  
medium_pizza = Circle(12)
teaching_table = Circle(36)
round_room = Circle(11460)

print(medium_pizza)
print(teaching_table)
print(round_room)
```
{% endcode %}

***

### Execercise:

```python
class Student:

  # Instances student class
  def __init__(self, name, year):
    self.name = name
    self.year = year
    self.grades = []
  
  # Method to student, verify grade if type Grade.
  def add_grade(self, grade):
    if type(grade) is Grade:
      self.grades.append(grade)      

roger = Student("Roger van der Weyden", 10)
sandro = Student("Sandro Botticelli", 12)
pieter = Student("Pieter Bruegel the Elder", 8)

# Created class grade
class Grade:
  minimum_passing = 65
  
  # Constructor
  def __init__(self, score):
    self.score = score

# Add grade
pieter.add_grade(Grade(100))
```
