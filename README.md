# Project2
## CS161 | Project 2
We want to design and implement a file sharing system (like Dropbox) that protects user privacy. In particular, user files are always *encrypted* and *authenticated* on the server. In addition,
users can share files with each other.

## Available Tools
- UUID
- Datastore: Encrypted Server
- Keystore: A store for public keys.
- Public Key Encryption, RSA small messages. 
- Digital Signitures, RSA
- HMAC using 128 key, bytes
- Hash based key derivation function, make new key from key.
- Argon2key, use entropy to create new key from key.
- Symmetric Encryption, CTR mode.
  
## Part 1: Single User File Storage
### Security Gurantees:
- All data on the server will be 
  protected and only available to those with the secret key.
  Should not learn any information
  from encrypted file.
- The Server is allowed to know 
  the length of your files.
- The user can detect if server
  changed a file, may return older versions.

**InitUser(username string, password string)**
(userdataptr *User, err error)
```
1. What variables require storage in userdataptr?
2. Where should userdataptr be saved? Encryption?
3. How should the authenticity be revised?
```

**GetUser(username string, password string)**
(userdataptr *User, err error)
```
1. Shoud verify username, password authenticity
2. Retrieve the user structure from permanent storage.
```
**StoreFile(filename string, data []byte)**
```
1. Save file persistently in data store meeting security gurantees.
2. Filename does NOT have enough entropy, different
users should have no problems using same filename. 
```
**LoadFile(filename string) (data []byte, err error)**
```
1. This function returns the latest file known by filename
2. If it appears to be tampered with report an error.
```
**AppendFile(filename string, data []byte) (err error)**
```
1. Append data to the end of file (from filename).
2. Does not produce any file integrity checks.
3. This method is required to be fast, it should not load
all data on filename to append.
4. Ensure the return of a file is the old version and never
a mix of old + new content.
```