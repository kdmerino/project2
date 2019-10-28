# Project2
## CS161 | Project 2
### Kevin Merino & Isabele Daniels
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
1. Determine UUID for encrypted file in Datastore server.
   Firstly, grab SALT from the user's filemap. Append salt to filename in a byte slice. Deterministically compute UUID from bytes.
2. Retrieve encrypted bytes from data store via UUID.
3. The file's key is recovered from User's struct personal key hashing the SALT via `HMACEval`. Decrypt into bytes of (metafile struct.)
4. Define variable to hold metafile structure, call
`json.Unmarshal` on decrypted bytes and defined variable.
5. If error is nil, metafile structure will contain an
array of encrpyted pages (byte slices with fixed size) 
and corresponding MAC's. We generate a correspoding,
zeroeth key via `HMACEval` with 'Secret' + type encrypted
via the already recovered key.
All *i-th* keys will use the previous key, and a
variation of the original message + it's index.
6. Iterate over each page, verification is done by 
obtaining `HMACEval` using its key and page. This is 
checked against its corresponding mac via `HMACEqual`.
7. Once verification is complete, decrypt all pages
via `SymDec` using corresponding key.

Notice, this technique allows us quickly append to a file
by accessing the last page in a slice. After verification
and encryption we may append ot this page. Thereby
reducing our access time to a constant (page size).

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
1. myUUID := uuid.New()
2.  - fileKey := HMACEval(User.personalKey, filename)
    - pageMsg := "PAGE" + filename
    - pageKey, _ := HMACEval(fileKey, pageMsg)
    - macsMsg := "MACS" + filename
    - macsKey, _ := HMACEval(fileKey, macsMsg)
3. myFile, a new ServerFile structure
4. numPages := len(data) / page_size
5. myFile.pages := make([][]bytes, 0, numPages)
7. myFile.MACs := make([][]bytes, 0, numPages)
8. for index from 0 to numPages - 1:
    t0, t1 := index * page_size, (index + 1) * page_size
    pagemsg := pageMsg + "index:" + str(index)
    pagekey := HMACEval(pageKey, pagemsg)
    page := SymEnc(pagekey, RandomBytes(128), data[t0:t1])
    macKey := HMACEVal(macsKey, page)
    append(myFile.pages[index], page)
    append(myfile.macs[index], macKey)
9. DatastoreSet(myUUID, SymEnc(fileKey, RandomBytes(128), myFile))
10. User.fileUUIDs[filename] = myUUID
11. User.update()
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


   

