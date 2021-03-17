# pattern-analyzer
A tool which will aid you in finding password-patterns

## What is it?
Imagine, during a legal pentest, you get your hands on a bunch of passwords and notice, that some people are using similiar patterns.
From a psychological point of view, this might indicate, that their IT department is setting initial passwords in a specific pattern, that gets adapted or simply incremented by their users.

This tool will parse a given list of passwords (one per line) and spits out patterns, sorted by the number of occurances, that can be used for further bruteforcing with tools like hashcat.

## Disclaimer
This program is inteded for legal use (e.g. during a pyed pentest) only. Never use it without explicit permission.
