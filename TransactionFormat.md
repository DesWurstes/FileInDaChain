Everything is little endian.

## Old Style Transaction Format Documentation

First 4 bytes: an unsigned integer that shows the length (bytes) of the transaction
Next 4 bytes: CRC32 hash of the raw data.
The last output is the change.
The previous output is the destination address.

## New Style Transaction Format Documentation (WIP)

*Everything is little endian.*

First 4 bytes: an unsigned integer that shows the length (bytes) of the transaction
Next 4 bytes: CRC32 hash of the raw data.
The last output is the change.

## MultiTrans big


---THIS FILE IS ABANDONED!!!---
