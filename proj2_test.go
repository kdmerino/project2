package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	"encoding/json"
	_ "encoding/json"
	"errors"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

// +---------------------------+ My Code Below Here +---------------------------+
func TestGetUser(t *testing.T) {
	t.Log("Getting a User test")
	userlib.SetDebugStatus(true)
	u, err := InitUser("kevin", "wasHere")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Got User", u)
	t.Log("Fetching User")
	user, e := GetUser("kevin", "wasHere")
	if e != nil {
		t.Error("Failed to Fetch User", e)
		return
	}
	// Matching fields?
	if u.Username == user.Username {
		t.Log("Username matched")
		match := true
		for i := 0; i < len(u.PersonalKey); i++ {
			if u.PersonalKey[i] != user.PersonalKey[i] {
				match = false
				break
			}
		}
		if match {
			t.Log("Personal Key was a match")
		} else {
			t.Log("Personal Key was corrupted with out detection")
		}
	}
	t.Log("Fetched ", user)

}

func TestMethodUser(t *testing.T) {
	// Simulate call: InitUser(username, password)
	t.Log("Starting Deep Test | InitUser")
	var userdata *User
	var err error

	username := "TestUser"
	password := "TestPassword"

	userPass := []byte(password)
	userKey := userlib.Argon2Key(userPass, []byte(username), 16)
	userName := userlib.Argon2Key(userKey, []byte(username), 16)
	id := bytesToUUID(userName)
	var user User

	signUser, verifyUser, _ := userlib.DSKeyGen()
	lockBlock := userlib.RandomBytes(16)
	privateKey := userlib.Argon2Key(userKey, lockBlock, 16)
	var public userlib.PKEEncKey // RSA for file Sharing

	// Fill in User fields
	user.Username = username
	user.Signature = signUser
	user.PersonalKey = userlib.Argon2Key(privateKey, userlib.RandomBytes(16), 16)
	public, user.RSAKey, _ = userlib.PKEKeyGen()
	user.UpdateKey = userKey
	user.FileUUIDs = nil
	user.FileKeys = nil
	user.Address = id

	// Post
	userlib.KeystoreSet("fs:"+username, public)
	userlib.KeystoreSet("sg:"+username, verifyUser)
	// Simulate call: CommitUser(userPTR, block)
	userdata = &user
	block := lockBlock
	outerKey := userdata.UpdateKey
	innerKey := userlib.Argon2Key(outerKey, block, 16)

	t.Log("Starting Deep Test | CommitUser")
	var sUser SignedUser
	// Encrypt
	bUser, marErr := json.Marshal(userdata)
	if marErr != nil {
		t.Error("Failure to Marshal user")
	}
	sUser.MyUser = userlib.SymEnc(innerKey, userlib.RandomBytes(16), bUser)
	sUser.MyLock = userlib.SymEnc(outerKey, userlib.RandomBytes(16), block)
	sUser.LockSign, err = userlib.DSSign(userdata.Signature, sUser.MyLock)
	if err != nil {
		t.Error("Lock Sig error", err)
	}
	sUser.UserSign, err = userlib.DSSign(userdata.Signature, sUser.MyUser)
	if err != nil {
		t.Error("User sig error", err)
	}
	// Commit
	bsUser, mar := json.Marshal(sUser)
	if mar != nil {
		t.Error("Could not marshal user")
	}
	encryptUser := userlib.SymEnc(outerKey, userlib.RandomBytes(16), bsUser)
	userlib.DatastoreSet(userdata.Address, encryptUser)
	t.Log("Ending Deep Test | CommitUser")
	t.Log("Ending Deep Test | InitUser")

	// Simulate call: GetUser(username, password)
	t.Log("Starting Deep Test | GetUser")
	var userdataptr *User
	UserPass := []byte(userPass)
	UserKey := userlib.Argon2Key(UserPass, []byte(username), 16)
	UserName := userlib.Argon2Key(UserKey, []byte(username), 16)
	userUUID := bytesToUUID(UserName)

	t.Log("Starting Deep Test | PullUser")
	// Simulate call: PullUser(userUUID, username, userKey)
	var data []byte
	outerKey = UserKey

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
					data = userlib.SymDec(innerKey, sUser.MyUser)
					t.Log("Sucessfully recovered data.")
				} else if lockErr == nil {
					t.Error("Lock Signature Failed")
				} else {
					t.Error("User signature failed")
				}
			} else {
				t.Error("User cannot be verified")
			}
		} else {
			t.Error("Failed to decrypt user", err)
		}
	} else {
		t.Error("User Not found")
	}
	t.Log("Ending Deep Test | PullUser")
	err = json.Unmarshal(data, &user)
	if err != nil {
		t.Error("Unmarshalling error, damaged?")
	}
	userdataptr = &user
	t.Log("Ending Deep Test | GetUser")
	t.Log("Comparing Results")
	if userdataptr.Address != userdata.Address {
		t.Error("User address data does NOT match")
	}
	if userdataptr.Username != userdata.Username {
		t.Error("User name does not match...")
	}
	for i := 0; i < len(userdataptr.PersonalKey); i++ {
		if userdataptr.PersonalKey[i] != userdata.PersonalKey[i] {
			t.Error("User keys did NOT match.")
		}
	}
	t.Log("User Record Matches...")

}

func TestMethodFile(t *testing.T) {
	var user *User
	var err error
	t.Log("Creating a User")
	username := "TestUser2"
	userpass := "123Password"
	user, err = InitUser(username, userpass)
	if err != nil {
		t.Error("Init Failure")
		return
	}
	t.Log("Starting Deep Test | StoreFile")
	filename := "TestFile1"
	data := []byte("Test Content Files...")
	// Simulating call: u.StoreFile(filename, filedata)
	var userdata *User
	var master FileMaster
	var rights Permission
	userdata = user

	fileUUID := uuid.New()
	headUUID := uuid.New()
	// Key is to be saved by each individual user
	fileKey, _ := userlib.HMACEval(userdata.PersonalKey, userlib.RandomBytes(16))
	fileKey = fileKey[:16]
	// Deterministic MAC
	macKey, _ := userlib.HMACEval(fileKey, []byte("file-mac-key"))
	macKey = macKey[:16]

	// Encrypt Data + Commit
	t.Log("Starting Deep Test | CommitFile")
	// Simulate Call: CommitFile(headUUID, data, fileKey, macKey)
	var sFile SignedFile
	// Encrypt Data + Commit
	EFile := userlib.SymEnc(fileKey, userlib.RandomBytes(16), data)
	sFile.ENCData = EFile
	sFile.MACData, _ = userlib.HMACEval(macKey, EFile)
	BFile, _ := json.Marshal(sFile)
	BEFile := userlib.SymEnc(fileKey, userlib.RandomBytes(16), BFile)
	userlib.DatastoreSet(headUUID, BEFile) // Store Encrypted Header
	t.Log("Ending Deep Test | CommitFile")

	// Buid Master File
	master.UIDBlocks = make([]uuid.UUID, 1)
	master.UIDBlocks[0] = headUUID
	magic := string(userlib.RandomBytes(16))
	rights.Valid = true
	rights.Root = true
	if master.Authorize == nil {
		master.Authorize = make(map[string]Permission)
	}
	t.Log("Using Key: ", []byte(magic))
	master.Authorize[magic] = rights // rights.Ref = nil
	t.Log("Giving user permission: ", rights)

	// Encrypt Master + Commit
	BMaster, _ := json.Marshal(master)
	t.Log("Starting Deep Test | CommitFile")
	// Simulate Call: CommitFile(fileUUID, BMaster, fileKey, macKey)
	// Encrypt Data + Commit
	EFile = userlib.SymEnc(fileKey, userlib.RandomBytes(16), BMaster)
	sFile.ENCData = EFile
	sFile.MACData, _ = userlib.HMACEval(macKey, EFile)
	BFile, _ = json.Marshal(sFile)
	BEFile = userlib.SymEnc(fileKey, userlib.RandomBytes(16), BFile)
	userlib.DatastoreSet(fileUUID, BEFile) // Store Encrypted Header
	t.Log("Ending Deep Test | CommitFile")
	// Authorize User
	if userdata.FileUUIDs == nil {
		userdata.FileUUIDs = make(map[string]uuid.UUID)
		userdata.FileKeys = make(map[string][]byte)
		userdata.FilePerms = make(map[string]string)
	}
	userdata.FileUUIDs[filename] = fileUUID
	userdata.FilePerms[filename] = magic
	userdata.FileKeys[filename] = fileKey

	// Commit User data
	t.Log("Updating User")
	LockBlock := userlib.RandomBytes(16)
	CommitUser(userdata, LockBlock)
	t.Log("Ending Deep Test | StoreFile")
	t.Log("Retrieved User")
	t.Log("Checking User Parameters")
	user, err = GetUser(username, userpass)

	if err != nil {
		t.Error("User retrieval failure", err)
	}
	for i := 0; i < len(fileKey); i++ {
		if fileKey[i] != user.FileKeys[filename][i] {
			t.Error("file key has changed...")
		}
	}
	// Pulling File from User
	// simulating PullFile(fileUUID, fileKey, macKey)
	// Decrypt Signed File
	t.Log("Starting Deep Test | PullFile")
	var signed SignedFile
	var ok bool
	data, ok = userlib.DatastoreGet(fileUUID)
	if ok {
		data = userlib.SymDec(fileKey, data)
		err = json.Unmarshal(data, &signed)
		if err == nil {
			// Integrity and Authenticity
			MACFile, _ := userlib.HMACEval(macKey, signed.ENCData)
			if userlib.HMACEqual(MACFile, signed.MACData) {
				// Decrypt Inner data
				t.Log("Master file recovered")
				data = userlib.SymDec(fileKey, signed.ENCData)
			} else {
				t.Error("MAC authentication of file failed")
			}
		} else {
			t.Error("Data could not be recovered")
		}
	} else {
		t.Error("File was not found in memory.")
	}
	var RetFile FileMaster
	var myFile []byte
	err = json.Unmarshal(data, &RetFile)
	t.Log("Diving into table")
	t.Log("Key expected: ", []byte(user.FilePerms[filename]))
	for key, val := range RetFile.Authorize {
		t.Log("Magic held:", []byte(key))
		t.Log("Permi held:", val)
	}

	if err == nil {
		t.Log("File Master retrieved")
		t.Log("Verifying user permissions")
		// Simulating Authorize(master, username, key)
		t.Log("Starting Deep Test | Authorize")
		perm := user.FilePerms[filename]
		var rights Permission
		for rights = RetFile.Authorize[perm]; !rights.Root; rights = RetFile.Authorize[rights.Ref] {
			t.Log("Current rights:", rights)
			if !rights.Valid {
				break
			}
		}
		t.Log("User reports Permission:", rights)
		if rights.Valid {
			t.Log("Ending Deep Test | Authorize")
			// User is Authorized, Load Data and perform all checks
			var header SignedFile
			for _, v := range RetFile.UIDBlocks {
				// Fetch Block of data and Decrypt
				BEHead, found := userlib.DatastoreGet(v)
				if !found {
					t.Error("Data block not found...")
				}
				// Securiy checks for this block
				BHead := userlib.SymDec(fileKey, BEHead)
				err = json.Unmarshal(BHead, &header)
				if err != nil {
					t.Error("File block was damaged")
				}
				DataMac, _ := userlib.HMACEval(macKey, header.ENCData)
				if !userlib.HMACEqual(DataMac, header.MACData) {
					err = errors.New("File has been tampered with")
				}
				// Append Decrypted Data Block
				BData := userlib.SymDec(fileKey, header.ENCData)
				for _, b := range BData {
					myFile = append(myFile, b)
				}
			}
		} else {
			t.Error("Authorization failure")
		}
	} else {
		t.Error("User file was damaged")
	}
	t.Log("--File was recovered--")
	t.Log(">>", string(myFile))
	t.Log("Ending Deep Test | PullFile")
	t.Log("Reloading User")
	t.Log("Starting Deep Test | AppendFile")
	MyUser, err := GetUser(username, userpass)
	if err != nil {
		t.Error("Could not retrieve user", err)
	}
	msg := []byte("> Appending to File: Hello World")
	// Simulating AppendFile(filename, data)
	// Get Master File from User's UUIDs
	data = msg
	FileUUID := MyUser.FileUUIDs[filename]
	HeadUUID := uuid.New()
	var Master FileMaster
	// Key is to be saved by each individual user
	FileKey := MyUser.FileKeys[filename]
	if fileKey == nil {
		err = errors.New("User did not save file key")
		return
	}
	// Deterministic MAC
	MacKey, _ := userlib.HMACEval(FileKey, []byte("file-mac-key"))
	MacKey = MacKey[:16]

	// Encrypt Data
	CommitFile(HeadUUID, data, FileKey, MacKey)

	// Decrypt Signed File
	BMaster, ok = PullFile(FileUUID, FileKey, MacKey)
	if !ok {
		t.Error("File was not found in server")
	}
	err = json.Unmarshal(BMaster, &Master)
	if err != nil {
		t.Error("File has been damaged", err)
	}
	// Enforce Permission policy
	t.Log("Starting Deep Test | Authorize")
	MyPerm := MyUser.FilePerms[filename]
	var Rights Permission
	for Rights = Master.Authorize[MyPerm]; !Rights.Root; Rights = Master.Authorize[Rights.Ref] {
		t.Log("Current rights:", Rights)
		if !Rights.Valid {
			break
		}
	}
	t.Log("Ending Deep Test | Authorize")
	if Rights.Valid {
		t.Log("User was authorized")
	} else {
		t.Error("User is not authorized")
		return
	}
	// Update Master
	Master.UIDBlocks = append(Master.UIDBlocks, HeadUUID)

	// Encrypt and Re-UpLoad
	BMaster, _ = json.Marshal(Master)
	CommitFile(FileUUID, BMaster, FileKey, MacKey)
	t.Log("Ending Deep Test | AppendFile")
	t.Log("Starting Deep Test | LoadFile")
	var Bmaster, MyFile []byte
	var newMaster FileMaster
	// Grab Master File once again.
	Bmaster, ok = PullFile(FileUUID, FileKey, MacKey)
	if !ok {
		t.Error("File was lost")
	}
	err = json.Unmarshal(Bmaster, &newMaster)
	if err != nil {
		t.Error("File has been damaged", err)
	}
	// Enforce Permission policy
	t.Log("Starting Deep Test | Authorize")
	for Rights = Master.Authorize[MyPerm]; !Rights.Root; Rights = Master.Authorize[Rights.Ref] {
		t.Log("Current rights:", Rights)
		if !Rights.Valid {
			break
		}
	}
	t.Log("Ending Deep Test | Authorize")
	if Rights.Valid {
		t.Log("User was authorized")
	} else {
		t.Error("User is not authorized")
		return
	}
	// User is Authorized, Load Data and perform all checks
	for _, v := range newMaster.UIDBlocks {
		var header SignedFile
		// Fetch Block of data and Decrypt
		BEHead, found := userlib.DatastoreGet(v)
		if !found {
			err = errors.New("File is corrupted")
			return
		}
		// Securiy checks for this block
		BHead := userlib.SymDec(FileKey, BEHead)
		err = json.Unmarshal(BHead, &header)
		if err != nil {
			return
		}
		DataMac, _ := userlib.HMACEval(macKey, header.ENCData)
		if !userlib.HMACEqual(DataMac, header.MACData) {
			err = errors.New("File has been tampered with")
			return
		}
		// Append Decrypted Data Block
		BData := userlib.SymDec(FileKey, header.ENCData)
		for _, b := range BData {
			MyFile = append(MyFile, b)
		}
	}

	t.Log("--File Updated--")
	t.Log(">> ", string(MyFile))
	t.Log("Ending Deep Test | LoadFile")
}

func TestStoreFile(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to build user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

// +---------------------------+ My Code Above Here +---------------------------+

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}
