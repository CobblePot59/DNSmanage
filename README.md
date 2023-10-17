# DNSmanage
The provided script is a Python program that interacts with an Active Directory (AD) server using the LDAP protocol. It allows you to perform various operations on DNS entries such as get, add, modify, and delete.

## General Help
![alt text](https://raw.githubusercontent.com/CobblePot59/DNSmanage/main/pictures/DNSmanage.jpg)

## Modules Help
#### get_entries
Searches for and returns all DNS entries.
```sh
DNSmanage.py -M get_entries
```
#### get_entry
Searches for and returns a specific DNS entry based on its name value.
```sh
DNSmanage.py -M get_entry --data 'quad9'
```
#### add_entry
Adds entry to the DNS server.
```sh
DNSmanage.py -M add_entry ---data 'quad9' '149.112.112.112'
```
#### modify_entry
Modifies attributes of a specified DNS entry.
```sh
DNSmanage.py -M modify_entry --data 'quad9' '9.9.9.9'
```
#### del_entry
Deletes a specified DNS entry.
```sh
DNSmanage.py -M del_entry --data 'quad9'
```
