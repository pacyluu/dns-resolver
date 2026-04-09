# DNS Resolver

A bare bones DNS Resolver that lets you enter a domain name, and prints out each name server it visits.

## Features

- Find the path a DNS query takes!

## How It Works

The application follows a straightforward pipeline:

1. The program querys "198.41.0.4", which is a.root-servers.net
2. Given authority and/or additional records, the resolver will send another query
3. The program stops once we receive an answer record

## Supported Record Types

- NS
- A

If you have any requests to make, don't hesitate to contact me

### Prerequisites

Make sure you have the following installed:

- Python >= 3.8

### Usage

From the project root, start the CLI with:
```
python3 main.py
```
