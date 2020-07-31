# dbus-parsec
DBus PARSEC interface

This project implements a DBus service that can store/retrieve secrets that are
encrypted with [PARSEC](https://github.com/parallaxsecond/parsec) keys.

* THIS PROJECT IS STILL IN DEVELOPMENT

## TODOs

* [ ] Configuration

## Implemented interfaces

### Control
There is a Control interface that can be used to store new secrets.

## NetworkManager SecretAgent
This interface is used to allow NetworkManager to retrieve stored credentials
for connections.
