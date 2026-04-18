# Password-Security-Checker
A simple password Security Checker using entropy, breach history and pattern detection.
This password security checker uses the [Have I Been Pwned](https://haveibeenpwned.com) Pwned Passwords API by Troy Hunt.

# OS:
This project was built and tested on Linux, it can be supported by windows by replacing <termios.h> for <conio.h> and changing the backspace character from 127 to 8

# Dependencies:
C compiler

python3-requests (sudo apt install python3-requests)


# Compile guide:
build with "gcc main.c -o main -lm"

run the code with "./main"

# Details:
The password checker scores each password inputted based on entropy, breach history and pattern detection.

Entropy: 33 points

Dictionary: 34 points

pattern detection: 33 points (20 points to sequence detection and 13 points to pattern detection)

The entropy is calculated with the length of the password in bits and the pool of characters.

The breach history / dictionary security checker uses the Pwned Passwords API by Troy Hunt to check whether the inputted password is on their database of pwned passwords.

The pattern detection is rudimentary. Essentially it just looks for basic patterns like repeated characters and sequenced numbers.
