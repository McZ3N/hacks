---
description: >-
  Setup for Parrot OS based on Hack the Box modules and boxes. Its personal
  prefence based on a minimal setup.
icon: debian
cover: ../.gitbook/assets/Schermafbeelding 2024-10-11 151559.png
coverY: 0
---

# Parrot OS - Setup

<figure><img src="../.gitbook/assets/Schermafbeelding 2024-10-11 153717.png" alt=""><figcaption></figcaption></figure>

### Install parrot

Start by installing Parrot OS, download from [https://parrotsec.org/download/](https://parrotsec.org/download/). It will download a Open Virtualization Format Archive (.ova) which you can double click and it will open in Virtual box. After adding the machine, increase processors and RAM memory and VRAM.

{% hint style="info" %}
VRAM by default cannot be increased higher than 128.  To change this run this command and then set vram to 256.\


```powershell
# Go to folder
cd C:\Program Files\Oracle\VirtualBox\ 

# Run cmd
VBoxManage.exe modifyvm "Parrot" --vram 256
```
{% endhint %}

### Setup Tmux

Some personal but practical minimal preferences for tmux. In Edit - Profile preference setup custom command as Tmux. This will startup tmux when opening the terminal.\


<details>

<summary>.tmux.conf</summary>

```
# Set shell for tmux
set-option -g default-command bash
set-option -g default-shell "/bin/bash"

# Increases the scrollback limit to 10,000 lines.
set -g history-limit 10000
set -g allow-rename off

# Status bar background color
set -g status-bg "#008000"

# Keybinds
bind-key j command-prompt -p "join pain from:" "join-pane -s '%%'"
bind-key s command-prompt -p "send pane to:" "join-pane -t '%%'"
bind-key C send-keys " | xclip -selection clipboard"

# keybindings for copy mode
set-window-option -g mode-keys vi

# Enable 256-color mode
set -g default-terminal "xterm-256color"
```

</details>

<figure><img src="../.gitbook/assets/Schermafbeelding 2024-10-11 153508.png" alt=""><figcaption></figcaption></figure>

### Setup .bashrc

Slightly modified .bashrc file. Its now showing either your local or when connected to the VPN, the vpn IP. It also has completion feature in here which will complete your input when pressing TAB.

<figure><img src="../.gitbook/assets/Schermafbeelding 2024-10-11 154109.png" alt=""><figcaption></figcaption></figure>

<details>

<summary>.bashrc </summary>

```bash
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

export PATH=~/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:$PATH

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
#[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	    color_prompt=yes
    else
	    color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\] "
else
    PS1='┌──[\u@\h]─[\w]\n└──╼ \$ '
fi

# Set 'man' colors
if [ "$color_prompt" = yes ]; then
	man() {
	env \
	LESS_TERMCAP_mb=$'\e[01;31m' \
	LESS_TERMCAP_md=$'\e[01;31m' \
	LESS_TERMCAP_me=$'\e[0m' \
	LESS_TERMCAP_se=$'\e[0m' \
	LESS_TERMCAP_so=$'\e[01;44;33m' \
	LESS_TERMCAP_ue=$'\e[0m' \
	LESS_TERMCAP_us=$'\e[01;32m' \
	man "$@"
	}
fi

unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*|tmux*)
    VPN=$(ps -ef | grep 'openvpn [eu|au|us|sg]'|tail -1| rev| awk '{print $1}'|rev |sed 's/\..*$//g')
    IP=$(ip -4 -o addr show enp0s3|awk '{print $4}'|sed 's/\/.*$//g')
    if [ ! -z "$VPN" ]; then
      IP=$(ip -4 -o addr show tun0|awk '{print $4}'|sed 's/\/.*$//g')
    fi
    PS1="\[\033[1;32m\]\342\224\214\342\224\200\$([[ \${IP} == *\"10.\"* ]] && echo \"[\[\033[1;34m\]\${VPN}\[\033[1;32m\]]\342\224\200\033[1;37m\]\[\033[1;32m\]\")[\[\033[1;37m\]\${IP}\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\u\[\033[01;32m\]@\[\033[01;34m\]\h\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\w\[\033[1;32m\]]\n\[\033[1;32m\]\342\224\224\342\224\200\342\224\200\342\225\274 [\[\e[01;33m\]★\[\e[01;32m\]]\\$ \[\e[0m\]"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -lh'
alias la='ls -lha'
alias l='ls -CF'
alias em='emacs -nw'
alias dd='dd status=progress'
alias _='sudo'
alias _i='sudo -i'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

# path
export PATH=$PATH:/home/mczen/scripts
```

</details>

## Install tools

Install several tools you will need. I personally use 1 folder and added this to path so when using scripts I dont have to use full paths like /usr/bin/python/smbclient.py but I can just use smbclient.py.\


### Impacket

```bash
# Install pipx
sudo pipx ensurepath

# Clone and install
git clone https://github.com/fortra/impacket
sudo pipx install .
```

Use the original folder or a directory of choice and export PATH=$PATH:/home/mczen/scripts. This way all scripts can be called by just the filename.&#x20;

### More installs

```bash
# install json
sudo apt-get install jq

# install wordlists
git clone https://github.com/danielmiessler/SecLists

# install kerbrute
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make linux
```







