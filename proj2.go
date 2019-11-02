package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// +---------------------------+ My Code Below Here +---------------------------+
// Wrapper Structures, hold signatures.
// SignedFile Structure, Holds Signature of Inner data (encrypted)
type SignedFile struct {
	ENCData []byte // Encrypted File Master
	MACData []byte // Master MAC code
}

// Permission Structure, Maintains user validity and reference to inviter
type Permission struct {
	Valid bool   // Check if Permission has NOT been revoked
	Root  bool   // Check if Permission is final authority
	Ref   string // Validity is dependent on Reference validity
}

// FileMaster Structure, holds permissions and UUID of blocks of data
type FileMaster struct {
	UIDBlocks []uuid.UUID           // UUID of i-th Enc Block of Data
	Authorize map[string]Permission // Chain of Permissions, uses fileID
}

// SendFile Structure, holds information needed to share file
type SendFile struct {
	Permission string    // Holds User to File permission Key
	FileUUID   uuid.UUID // UUID for File to be shared
	FileKeys   []byte    // Key to access File to be shared
}

// SignedUser Structure, Holds seed for next key + signatures
type SignedUser struct {
	MyUser   []byte // Inner Encrypted User
	MyLock   []byte // Block of Ramdom Data for inner key.
	LockSign []byte // Lock Signature
	UserSign []byte // User Signature
}

// +---------------------------+ My Code Above Here +---------------------------+

// The structure definition for a user record
type User struct {
	Username string
	// +---------------------------+ My Code Below Here +---------------------------+
	Signature   userlib.DSSignKey    // Signature key for Outter block
	RSAKey      userlib.PKEDecKey    // RSA Decryption Key (Private)
	PersonalKey []byte               // Unique Key for this user's purposes.
	UpdateKey   []byte               // Outter Key for this user's updates.
	Address     uuid.UUID            // UUID of self
	FileUUIDs   map[string]uuid.UUID // Map of User's files from filename to UUID
	FileKeys    map[string][]byte    // Map of User's files from filename to key
	// +---------------------------+ My Code Above Here +---------------------------+

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

// +---------------------------+ My Code Below Here +---------------------------+

// CommitUser heler method to Encrypt and Commit User to memory.
func CommitUser(userptr *User, block []byte) {
	var sUser SignedUser
	outerKey := userptr.UpdateKey
	innerKey := userlib.Argon2Key(outerKey, block, 16)
	// Encrypt
	bUser, _ := json.Marshal(userptr)
	sUser.MyUser = userlib.SymEnc(innerKey, userlib.RandomBytes(16), bUser)
	sUser.MyLock = userlib.SymEnc(outerKey, userlib.RandomBytes(16), block)
	sUser.LockSign, _ = userlib.DSSign(userptr.Signature, sUser.MyLock)
	sUser.UserSign, _ = userlib.DSSign(userptr.Signature, sUser.MyUser)
	// Commit
	bsUser, _ := json.Marshal(sUser)
	encryptUser := userlib.SymEnc(outerKey, userlib.RandomBytes(16), bsUser)
	userlib.DatastoreSet(userptr.Address, encryptUser)
}

// PullUser helper method to Pull and Decrypt + Verify a User from memory.
func PullUser(userUUID uuid.UUID, username string, outerKey []byte) (data []byte, err error) {
	var sUser SignedUser
	// Pull User
	BEUser, found := userlib.DatastoreGet(userUUID)
	if found {
		BUser := userlib.SymDec(outerKey, BEUser)
		err = json.Unmarshal(BUser, &sUser)
		if err == nil {
			// Verify the integrity of User, and Lock
			verify, ok := userlib.KeystoreGet("sg:" + username)
			if ok {
				lockErr := userlib.DSVerify(verify, sUser.MyLock, sUser.LockSign)
				userErr := userlib.DSVerify(verify, sUser.MyUser, sUser.UserSign)
				if lockErr == nil && userErr == nil {
					block := userlib.SymDec(outerKey, sUser.MyLock)
					innerKey := userlib.Argon2Key(outerKey, block, 16)
					data := userlib.SymDec(innerKey, sUser.MyUser)
					err = nil
					return data, err
				}
				data = nil
				if lockErr == nil {
					err = userErr
				} else {
					err = lockErr
				}
			} else {
				data = nil
				err = errors.New("User cannot be verified")
			}
		} else {
			data = nil
			err = errors.New("Failed to decrypt user")
		}
	} else {
		data = nil
		err = errors.New("User Not found")
	}
	return data, err
}

// CommitFile helper method to Encrypt and Commit a File to memory.
func CommitFile(fileUUID uuid.UUID, file []byte, fileKey []byte, macKey []byte) {
	var sFile SignedFile
	// Encrypt Data + Commit
	EFile := userlib.SymEnc(fileKey, userlib.RandomBytes(16), file)
	sFile.ENCData = EFile
	sFile.MACData, _ = userlib.HMACEval(macKey, EFile)
	BFile, _ := json.Marshal(sFile)
	BEFile := userlib.SymEnc(fileKey, userlib.RandomBytes(16), BFile)
	userlib.DatastoreSet(fileUUID, BEFile) // Store Encrypted Header
}

// PullFile helper method to Pull and Decrypt a File from memory.
func PullFile(fileUUID uuid.UUID, fileKey []byte, macKey []byte) (data []byte, ok bool) {
	// Decrypt Signed File
	var signed SignedFile
	data, ok = userlib.DatastoreGet(fileUUID)
	if ok {
		data = userlib.SymDec(fileKey, data)
		err := json.Unmarshal(data, &signed)
		if err == nil {
			// Integrity and Authenticity
			MACFile, _ := userlib.HMACEval(macKey, signed.ENCData)
			if userlib.HMACEqual(MACFile, signed.MACData) {
				// Decrypt Inner data
				data = userlib.SymDec(fileKey, signed.ENCData)
				return data, ok
			}
		}
	}
	return nil, false
}

// Authorized helper method to check a user's permissions given a master file.
func Authorized(master *FileMaster, perm string) bool {
	var rights Permission
	for rights = master.Authorize[perm]; !rights.Root; rights = master.Authorize[rights.Ref] {
		if !rights.Valid {
			break
		}
	}
	return rights.Valid
}

// +---------------------------+ My Code Above Here +---------------------------+

func InitUser(username string, password string) (userdataptr *User, err error) {
	// +---------------------------+ My Code Below Here +---------------------------+
	userPass := []byte(password)
	userKey := userlib.Argon2Key(userPass, []byte(username), 16)
	userName := userlib.Argon2Key(userKey, []byte(username), 16)
	id := bytesToUUID(userName)
	var user User

	signUser, verifyUser, _ := userlib.DSKeyGen()
	lockBlock := userlib.RandomBytes(16)
	var public userlib.PKEEncKey // RSA for file Sharing

	// Fill in User fields
	user.Username = username
	user.Signature = signUser
	user.PersonalKey = userlib.Argon2Key(userlib.RandomBytes(16), userlib.RandomBytes(16), 16)
	public, user.RSAKey, err = userlib.PKEKeyGen()
	user.UpdateKey = userKey
	user.FileUUIDs = nil
	user.FileKeys = nil
	user.Address = id

	// Post
	userlib.KeystoreSet("fs:"+username, public)
	userlib.KeystoreSet("sg:"+username, verifyUser)
	CommitUser(&user, lockBlock)

	// Ignore error handling for now
	userdataptr = &user
	return userdataptr, nil
	// +---------------------------+ My Code Above Here +---------------------------+
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// +---------------------------+ My Code Below Here +---------------------------+
	userPass := []byte(password)
	userKey := userlib.Argon2Key(userPass, []byte(username), 16)
	userName := userlib.Argon2Key(userKey, []byte(username), 16)
	userUUID := bytesToUUID(userName)
	var user User

	// Grab Signed User from Datastore
	BUser, err := PullUser(userUUID, username, userKey)
	if err == nil {
		err = json.Unmarshal(BUser, &user)
		userdataptr = &user
		return userdataptr, err

	}
	return nil, err
	// +---------------------------+ My Code Above Here +---------------------------+
}

// This stores a file in the datastore.
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// +---------------------------+ My Code Below Here +---------------------------+{
	var master FileMaster
	var rights Permission

	fileUUID := uuid.New()
	headUUID := uuid.New()
	// Key is to be saved by each individual user
	fileKey, _ := userlib.HMACEval(userdata.PersonalKey, userlib.RandomBytes(16))
	fileKey = fileKey[:16]
	// Deterministic MAC
	macKey, _ := userlib.HMACEval(fileKey, []byte("file-mac-key"))
	macKey = macKey[:16]

	// Encrypt Data + Commit
	CommitFile(headUUID, data, fileKey, macKey)

	// Buid Master File
	master.UIDBlocks = make([]uuid.UUID, 1)
	master.UIDBlocks[0] = headUUID
	rights.Valid = true
	rights.Root = true
	magic := userdata.Username
	if master.Authorize == nil {
		master.Authorize = make(map[string]Permission)
	}
	master.Authorize[magic] = rights // rights.Ref = nil

	// Encrypt Master + Commit
	BMaster, _ := json.Marshal(master)
	CommitFile(fileUUID, BMaster, fileKey, macKey)

	// Authorize User
	if userdata.FileUUIDs == nil {
		userdata.FileUUIDs = make(map[string]uuid.UUID)
		userdata.FileKeys = make(map[string][]byte)
	}
	userdata.FileUUIDs[filename] = fileUUID
	userdata.FileKeys[filename] = fileKey

	// Commit User data
	LockBlock := userlib.RandomBytes(16)
	CommitUser(userdata, LockBlock)

	// +---------------------------+ My Code Above Here +---------------------------+
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// +---------------------------+ My Code Below Here +---------------------------+
	latest, err := PullUser(userdata.Address, userdata.Username, userdata.UpdateKey)
	if err != nil {
		return
	}
	err = json.Unmarshal(latest, userdata)
	// Get Master File from User's UUIDs
	var master FileMaster

	fileUUID := userdata.FileUUIDs[filename]
	headUUID := uuid.New()
	// Key is to be saved by each individual user
	fileKey := userdata.FileKeys[filename]
	if fileKey == nil {
		err = errors.New("User did not save file key")
		return
	}
	// Deterministic MAC
	macKey, _ := userlib.HMACEval(fileKey, []byte("file-mac-key"))
	macKey = macKey[:16]

	// Encrypt Data
	CommitFile(headUUID, data, fileKey, macKey)

	// Decrypt Signed File
	BMaster, ok := PullFile(fileUUID, fileKey, macKey)
	if !ok {
		err = errors.New("File was not found in server")
	}
	err = json.Unmarshal(BMaster, &master)
	if err != nil {
		err = errors.New("File has been damaged")
		return
	}
	// Enforce Permission policy
	if !Authorized(&master, userdata.Username) {
		err = errors.New("User is NOT authorized")
		return
	}
	// Update Master
	master.UIDBlocks = append(master.UIDBlocks, headUUID)

	// Encrypt and Re-UpLoad
	BMaster, _ = json.Marshal(master)
	CommitFile(fileUUID, BMaster, fileKey, macKey)

	return nil // NO Error was detected

	// +---------------------------+ My Code Above Here +---------------------------+
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// +---------------------------+ My Code Below Here +---------------------------+
	// First, Reload the User to ensure latest files
	latest, err := PullUser(userdata.Address, userdata.Username, userdata.UpdateKey)
	if err != nil {
		return
	}
	err = json.Unmarshal(latest, userdata)

	// Get Master File from User's UUIDs
	var header SignedFile
	var master FileMaster

	fileUUID := userdata.FileUUIDs[filename]
	// Key is to be saved by each individual user
	fileKey := userdata.FileKeys[filename]
	if fileKey == nil {
		err = errors.New("File Key is lost")
		return
	}
	// Deterministic MAC
	macKey, _ := userlib.HMACEval(fileKey, []byte("file-mac-key"))
	macKey = macKey[:16]

	// Decrypt Signed File
	BMaster, ok := PullFile(fileUUID, fileKey, macKey)
	if !ok {
		err = errors.New("File was not found in server")
	}
	err = json.Unmarshal(BMaster, &master)
	if err != nil {
		err = errors.New("File has been damaged")
		return
	}
	// Obtain Master Permission
	magic := userdata.Username
	if !Authorized(&master, magic) {
		return nil, errors.New("Not authorized")
	}
	// User is Authorized, Load Data and perform all checks
	for _, v := range master.UIDBlocks {
		// Fetch Block of data and Decrypt
		BEHead, found := userlib.DatastoreGet(v)
		if !found {
			err = errors.New("File is corrupted")
			return data, err
		}
		// Securiy checks for this block
		BHead := userlib.SymDec(fileKey, BEHead)
		err = json.Unmarshal(BHead, &header)
		if err != nil {
			return data, err
		}
		DataMac, _ := userlib.HMACEval(macKey, header.ENCData)
		if !userlib.HMACEqual(DataMac, header.MACData) {
			err = errors.New("File has been tampered with")
			return data, err
		}
		// Append Decrypted Data Block
		BData := userlib.SymDec(fileKey, header.ENCData)
		for _, b := range BData {
			data = append(data, b)
		}
	}

	return data, nil // NO Error was detected

	// +---------------------------+ My Code Above Here +---------------------------+
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	// +---------------------------+ My Code Below Here +---------------------------+
	// Get User Updated Information
	latest, err := PullUser(userdata.Address, userdata.Username, userdata.UpdateKey)
	if err != nil {
		return
	}
	err = json.Unmarshal(latest, userdata)

	// Get Master File from User's UUIDs
	var signed SignedUser
	var send SendFile
	var master FileMaster
	var rights Permission

	fileUUID := userdata.FileUUIDs[filename]
	// Key is to be saved by each individual user
	fileKey := userdata.FileKeys[filename]
	// Deterministic MAC
	macKey, _ := userlib.HMACEval(fileKey, []byte("file-mac-key"))
	macKey = macKey[:16]

	// Decrypt Signed File
	BMaster, ok := PullFile(fileUUID, fileKey, macKey)
	if !ok {
		err = errors.New("File was not found in server")
	}
	err = json.Unmarshal(BMaster, &master)
	if err != nil {
		err = errors.New("File has been damaged")
		return
	}
	// Enforce Permission policy
	if !Authorized(&master, userdata.Username) {
		err = errors.New("User is NOT authorized")
		return
	}

	// User is Authorized, allow this user to share this file.
	//	bmagic, _ := userlib.HMACEval(macKey, []byte(recipient))
	magic := recipient
	rights.Ref = userdata.Username
	rights.Root = false
	rights.Valid = true
	master.Authorize[magic] = rights

	// Encrypt and Re-UpLoad
	BMaster, _ = json.Marshal(master)
	CommitFile(fileUUID, BMaster, fileKey, macKey)

	// Prepare Magic String for Sharing
	key := userlib.RandomBytes(16)
	recipientKey, _ := userlib.KeystoreGet("fs:" + recipient)
	EKey, enErr := userlib.PKEEnc(recipientKey, key)
	if enErr != nil {
		return "fail", errors.New("Key encrypt failure")
	}
	send.FileKeys = fileKey
	send.FileUUID = fileUUID
	send.Permission = magic
	bsend, _ := json.Marshal(send)

	signed.MyLock = EKey
	signed.MyUser = userlib.SymEnc(key, userlib.RandomBytes(16), bsend)
	signed.LockSign, _ = userlib.DSSign(userdata.Signature, EKey)
	signed.UserSign, _ = userlib.DSSign(userdata.Signature, signed.MyUser)
	BSigned, enERR := json.Marshal(signed)

	return string(BSigned), enERR // NO Error was detected

	// +---------------------------+ My Code Above Here +---------------------------+

}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	// +---------------------------+ My Code Below Here +---------------------------+
	// Force a user update
	latest, err := PullUser(userdata.Address, userdata.Username, userdata.UpdateKey)
	if err != nil {
		err = errors.New("Failed to pull update")
		return err
	}
	err = json.Unmarshal(latest, userdata)
	if err != nil {
		err = errors.New("Updates failed")
		return err
	}

	// Decrypt String into Sender file
	var sign SignedUser
	var pack SendFile
	// Turn String into a SignedUser
	err = json.Unmarshal([]byte(magic_string), &sign)
	if err != nil {
		return errors.New("Magic String build failed")
	}
	// Verify integrity of Lock and Inner data
	verify, ok := userlib.KeystoreGet("sg:" + sender) // Get Sender verification
	if !ok {
		return errors.New("Could not retrieve Verification")
	}
	err = userlib.DSVerify(verify, sign.MyLock, sign.LockSign)
	if err != nil {
		return errors.New("Lock Verification failed")
	}
	err = userlib.DSVerify(verify, sign.MyUser, sign.UserSign)
	if err != nil {
		return err
	}
	key, err := userlib.PKEDec(userdata.RSAKey, sign.MyLock)
	if err != nil {
		return err
	}
	BPack := userlib.SymDec(key, sign.MyUser)
	err = json.Unmarshal(BPack, &pack)
	if err != nil {
		return errors.New("File information corrupted")
	}

	// Obtain Ownership of file
	if userdata.FileKeys == nil {
		userdata.FileKeys = make(map[string][]byte)
		userdata.FileUUIDs = make(map[string]uuid.UUID)

	}
	userdata.FileKeys[filename] = pack.FileKeys
	userdata.FileUUIDs[filename] = pack.FileUUID
	// Commit User data
	LockBlock := userlib.RandomBytes(16)
	CommitUser(userdata, LockBlock)

	return nil // No error was detected
	// +---------------------------+ My Code Above Here +---------------------------+
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	// +---------------------------+ My Code Below Here +---------------------------+}
	// Update to latest user info
	latest, err := PullUser(userdata.Address, userdata.Username, userdata.UpdateKey)
	if err != nil {
		return
	}
	err = json.Unmarshal(latest, userdata)
	// Get Master File from User's UUIDs
	var master FileMaster

	fileUUID := userdata.FileUUIDs[filename]
	// Key is to be saved by each individual user
	fileKey := userdata.FileKeys[filename]
	// Deterministic MAC
	macKey, _ := userlib.HMACEval(fileKey, []byte("file-mac-key"))
	macKey = macKey[:16]

	// Decrypt Signed File
	BMaster, ok := PullFile(fileUUID, fileKey, macKey)
	if !ok {
		err = errors.New("File was not found in server")
	}
	err = json.Unmarshal(BMaster, &master)
	if err != nil {
		err = errors.New("File has been damaged")
		return
	}
	// Obtain Master Permission
	if !Authorized(&master, userdata.Username) {
		err = errors.New("User is not authorized")
		return
	}
	// Remove target's permissions
	//	tPerm, err := userlib.HMACEval(macKey, []byte(target_username))
	permRec := master.Authorize[target_username]
	permRec.Valid = false
	master.Authorize[target_username] = permRec

	// Update Master
	BMaster, err = json.Marshal(master)
	CommitFile(fileUUID, BMaster, fileKey, macKey)
	return nil
	// +---------------------------+ My Code Above Here +---------------------------+}
}
