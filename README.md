# Project2
## CS161 | Project 2
### Kevin Merino & Isabel Daniels
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

### User Verification
1. Determine UUID for encrypted signed-user structure in Datastore server.
Firstly, use `Argon2Key` on *password*, *user name*, 128.
Secondly, call `uuid.FromBytes` with the returned slice. 
2. Retrieve encrypted bytes from data store via UUID.
3. Decrypt bytes of signed-user structure using `SymDec`
with *key* set to user password.
4. Define variable to hold signed-user structure, call `json.Unmarshal` on decrypted bytes and defined variable.
5. If error is nil, signed-user will contain User struct, userUUID, userSignature, a slice of bytes, sliceSignature.
   Run `DSVerify` and procede if no tampering has occurred on either object. Signatures are available in keyStore by username, username + "lock".
6. Using `Aargon2Key` with user password, and the recovered slice of bytes create a 128 bit key.
7. Decrypt into bytes of User structure using `SymDec` with *key* 
as the 128 bit key just derived.
8. Define variable to hold User struct, call `json.Unmarshal` on decrypted bytes and defined variable.
9.  If error is nil, we have decrypted, verified interigity, and authenticity. 

Notice we use a decrypt, signature check, and decrypt again 
technique which protects the encrypted User via a signature and 
the signature is protected via a secondary encryption
containing both objects. Notice, we are resistant to tampering
since the random byte block to generate the secondary key is 
also protected via a signature.

### File Retrieval 
1. 


### Functions
**InitUser(username string, password string)**
(userdataptr *User, err error)
```
1. userID := Argon2Key(password.bytes(), user_name.bytes(), 128)
2. userUUID, _ := uuid.FromBytes(userID)
3. sUser, a new signedUser structure.
4. user, a new User structure.
5. lockBlock := RandomBytes(128)
6. privateKey := Argon2Key(password.bytes(), lockBlock, 128)
7. - user.personalKey := Argon2Key(privateKey, RandomBytes(128), 128)
   - user.fileUUIDs := map[string]UUID
   - user.username := user_name

8. signLock, verifyLock := DSKeyGen()
    - user.signLock := signLock
9. signUser, verifyUser := DSKeyGen() 
    - user.signUser := signUser
10. bUser, _ := json.Marshal(user)
11. sUser.myLock := SymEnc(password.bytes(), RandomBytes(256), lockBlock)
12. sUser.myUser := SymEnc(privateKey, RandomBytes(256), bUser)
13. sUser.lockSign := DSSign(signLock, sUser.myLock)
14. sUser.userSign := DSSign(signUser, sUser.myUser)
15. KeystoreSet(user_name, verifyUser)
16. KeystoreSet(user_name + 'lock', verifyLock)
17. DatastoreSet(userUUID, SymEnc(password.bytes(), RandomBytes(128), json.Marshal(sUser)))
18. Return &user
```

**GetUser(username string, password string)**
(userdataptr *User, err error)
```
1. Follow all steps of User Verification.
2. return &RetrievedUser
```
**StoreFile(filename string, data []byte)**
```
1. 
```
**LoadFile(filename string) (data []byte, err error)**
```
1. This function returns the latest file known by filename
2. If it appears to be tampered with report an error.
```
**AppendFile(filename string, data []byte) (err error)**
```
1. Append data to the end of file (from filename).
	- Retrieve last page and append recursively.
2. Does not produce any file integrity checks.
	- Write directly to the end page? How to seperate the encryption
	from the last page to the next. Is it necessary? The key is the
same in both files should be able to append.

3. This method is required to be fast, it should not load
all data on filename to append.
	- A page is pulled not the entire file.
4. Ensure the return of a file is the old version and never
a mix of old + new content.
	- Reduce the page size to bytes. Load to user struct once
all data has been processed. 

```


   

