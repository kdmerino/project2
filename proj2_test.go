package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
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
/*
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
	magic := username
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
	}
	userdata.FileUUIDs[filename] = fileUUID
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
	t.Log("Key expected: ", []byte(user.Username))
	for key, val := range RetFile.Authorize {
		t.Log("Magic held:", []byte(key))
		t.Log("Permi held:", val)
	}

	if err == nil {
		t.Log("File Master retrieved")
		t.Log("Verifying user permissions")
		// Simulating Authorize(master, username, key)
		t.Log("Starting Deep Test | Authorize")
		perm := user.Username
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
	MyPerm := MyUser.Username
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

func TestMethodSharing(t *testing.T) {
	u, err := InitUser("alice2", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("TestBob1", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize TestBob1", err2)
		return
	}
	x := []byte("This is a test")
	fileX := "fileX"
	u.StoreFile(fileX, x)

	var v, v2 []byte
	var magic string

	v, err = u.LoadFile(fileX)
	if err != nil {
		t.Error("Failed to download the file from alice2", err)
		return
	}

	magic, err = u.ShareFile("fileX", "TestBob1")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("fileY", "alice2", magic)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("fileY")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	err = u.RevokeFile("fileX", "TestBob1")
	if err != nil {
		t.Error("Revoke Failed", err)
	}
	v3, err2 := u2.LoadFile("fileY")
	if err2 == nil {
		t.Error("User still got a hold of the file")
	} else {
		t.Log("User error report:", err2)
		t.Log("User file report:", v3)
	}
}
*/

func TestInitMultiUsers(t *testing.T) {
	// Bulk Load Test Many Users
	load := 3
	name := make([]string, 1)
	pass := make([]string, 1)
	userptrs := make([]*User, 1)

	for i := 0; i < load; i++ {
		name = append(name, string(userlib.RandomBytes(4)))
		pass = append(name, string(userlib.RandomBytes(4)))
		user, err := InitUser(name[i], pass[i])
		if err != nil {
			t.Error("Error on user", string(i+1), ":", err)
		} else {
			userptrs = append(userptrs, user)
		}
	}
	// Test each user with all other passwords
	count, total := 0, 0
	for i := 0; i < load; i++ {
		for j := 0; j < load; j++ {
			// Skip the correct answer
			if i == j {
				continue
			}
			u, err := GetUser(name[i], pass[j])
			if err == nil {
				t.Error("Owned user [", string(i+1), "]:", u.Username)
				count++
				total++
			} else {
				total++
			}

		}
	}
	if count == 0 {
		t.Log("Protected all users")
	} else {
		t.Error("Forfit count: ", float64(count)/float64(total))
	}
}

// Test to see if a user can be revoked and respawned.
func TestInviteSpawn(t *testing.T) {
	a, _ := InitUser("A", "Apass")
	b, _ := InitUser("B", "Bpass")

	fileA := []byte("--This is A's File--")
	a.StoreFile("fileA", fileA)
	magic, err := a.ShareFile("fileA", "B")
	if err != nil {
		t.Error("error", err)
	}
	err = b.ReceiveFile("fileB", "A", magic)
	if err != nil {
		t.Error("error", err)
	}
	fileB, err := b.LoadFile("fileB")
	if err != nil {
		t.Error("error", err)
	}
	if !reflect.DeepEqual(fileA, fileB) {
		t.Error("Files are not the same")
	}
	err = a.RevokeFile("fileA", "B")
	_, err = b.LoadFile("fileB")
	if err == nil {
		t.Error("User received unauthorized access")
	}
	magic2, err := a.ShareFile("fileA", "B")
	if err != nil {
		t.Error("error", err)
	}
	err = b.ReceiveFile("fileB", "A", magic2)
	if err != nil {
		t.Error("error", err)
	}
	a.AppendFile("fileA", []byte("update 1a"))

	updateA, err := a.LoadFile("fileA")
	if err != nil {
		t.Error("error", err)
	}
	updateB, err := b.LoadFile("fileB")
	if err != nil {
		t.Error("error", err)
	}
	if !reflect.DeepEqual(updateA, updateB) {
		t.Error("User B did not receive updates")
	}
}

// Test to see if another user can open our file.
func TestOtherAccess(t *testing.T) {
	// Initialize users (A, B)
	A, err := InitUser("userA", "passA")
	if err != nil {
		t.Error("error", err)
	}
	B, err := InitUser("userB", "passB")
	if err != nil {
		t.Error("error", err)
	}
	// 	User A<- Creates file
	fileA := []byte("--This is file A--")
	A.StoreFile("fileA", fileA)
	//	User B<- Attempts to open the same file - via filename.
	_, err = B.LoadFile("fileA")
	if err == nil {
		t.Error("User gained unauthorized access")
	}
	//  User B<- makes a file with a new file with filename.
	fileB := []byte("--This is file B--")
	B.StoreFile("fileA", fileB)
	fileBA, err := B.LoadFile("fileA")
	if err != nil {
		t.Error("error", err)
	}
	//  Verify no leaks occured.
	if reflect.DeepEqual(fileA, fileBA) {
		t.Error("Filename led to leaks")
	}
}

/*
// Test to see if live updates occur
func TestMultiAccess(t *testing.T) {
	// Initialize Users, (A, B, C, D)
	A, err := InitUser("UserA", "passA")
	if err != nil {
		t.Error("error", err)
	}
	B, err := InitUser("UserB", "passB")
	if err != nil {
		t.Error("error", err)
	}
	C, err := InitUser("UserC", "passC")
	if err != nil {
		t.Error("error", err)
	}
	D, err := InitUser("UserD", "passD")
	if err != nil {
		t.Error("error", err)
	}
	// User A<- Creates a file, 'fileA'
	fileA := []byte("--This is file A--")
	A.StoreFile("fileA", fileA)
	magicB, err := A.ShareFile("fileA", "UserB")
	if err != nil {
		t.Error("error", err)
	}
	magicC, err := A.ShareFile("fileA", "userC")
	if err != nil {
		t.Error("error", err)
	}
	magicD, err := A.ShareFile("fileA", "userD")
	if err != nil {
		t.Error("error", err)
	}
	// User B<- Receives 'fileA' from A
	B.ReceiveFile("fileAB", "userA", magicB)
	// User C<- Receives 'fileA' from A
	C.ReceiveFile("fileAC", "userA", magicC)
	// User D<- Receives 'fileB' from A
	D.ReceiveFile("fileAD", "userA", magicD)
	// For all users [i]:
	Users := []*User{A, B, C, D}
	Files := []string{"fileA", "fileAB", "fileAC", "fileAD"}
	var file, cursor []byte
	for i := 0; i < len(Users); i++ {
		// Verify all users received update.
		err := Users[i].AppendFile(Files[i], []byte("update"))
		file, err = Users[i].LoadFile(Files[i])
		if err != nil {
			t.Error("User could not update file.", err)
		}
		for j := 0; j < len(Users); j++ {
			// User [i] updates 'file[i]' <-> 'fileA'
			if i != j {
				cursor, err = Users[j].LoadFile(Files[j])
				if !reflect.DeepEqual(file, cursor) {
					t.Error("User did not see update")
				}
			}
		}
	}

}

// test to see if a user can share a shared file.
func TestSharingShares(t *testing.T) {
	// Load Users, (A, B, C)
	A, err := GetUser("userA", "passA")
	if err != nil {
		t.Error("error", err)
	}
	B, err := GetUser("userB", "passB")
	if err != nil {
		t.Error("error", err)
	}
	C, err := GetUser("userC", "passC")
	if err != nil {
		t.Error("error", err)
	}
	// User A<- Creates a file, 'mutual'
	mutual := []byte("-- This is mutual --")
	A.StoreFile("mutual", mutual)
	magic, err := A.ShareFile("mutual", "userB")
	if err != nil {
		t.Error("error", err)
	}
	// User B<- Receives a file from A
	err = B.ReceiveFile("mutual", "userA", magic)
	if err != nil {
		t.Error("error", err)
	}
	magic2, err := B.ShareFile("mutual", "userC")
	if err != nil {
		t.Error("error", err)
	}
	// User C<- Receives 'mutual' from B
	err = C.ReceiveFile("mutual", "userB", magic2)
	if err != nil {
		t.Error("error", err)
	}
}

/*
// Test to see if a revoked user can access updates.
func TestRevokeUpdates(t *testing.T) {
	// Load Users, (A, C)
	A, err := GetUser("userA", "passA")
	C, err := GetUser("userC", "passC")
	// User A Revokes access to C
	err = A.RevokeFile("mutual", "userC")
	A.AppendFile("mutual", []byte("-A was here"))
	latest, err := A.LoadFile("mutual")
	err = A.RevokeFile("mutual", "userC")
	// Ensure C does not see update.
	update, err := C.LoadFile("mutual")
	if err == nil {
		t.Error("Update was not prevented")
	}
}

// Test to see if a revoked user's invitation is valid.
func TestRevokeFriends(t *testing.T) {
	// Load Users, (A, B, C)
	A, err := GetUser("userA", "passA")
	B, err := GetUser("userB", "passB")
	C, err := GetUser("userC", "passC")
	// User B invites C
	magic, err := B.ShareFile("mutual", "userC")
	err = C.ReceiveFile("mutual", "userB", magic)
}


// Test to see if a different user can use a magicstring.
func TestNotMyMagic(t *testing.T) {
	// Create Users, (x, Y, Z)
	X, err := InitUser("userX", "passX")
	Y, err := InitUser("userY", "passY")
	Z, err := InitUser("userZ", "passZ")
	// User X creates a file
	fileX := []byte("This is file X")
	X.StoreFile("fileX", fileX)
	magic, err := X.ShareFile("fileX", "userY")
	// User Z snoops magic_string and attempts
	// - 1. Pre Snoop
	err = Z.ReceiveFile("fileX", "userX", magic)
	// User Y receives file from X
	err = Y.ReceiveFile("fileX", "userX", magic)
	// - 2. Post Snoop
	err = Z.ReceiveFile("fileX", "userX", magic)
}

// Test to see if multiple user's can update the same file.
func TestMultiUpdates(t *testing.T) {
	// Load Users, (A, B, C)
	// User A Creates new 'fileA'
	// User B<- Receives 'fileA' from A
	// User C<- Receives 'FileB' from B
	// Ensure everyone sees updates
}

// Test to see if a revoked user can regain access via magic string.
func TestRecycleMagic(t *testing.T) {
	// Load Users X, Y
	// User Y receives file2 from X
	// User X revokes Y from file2
	// User Y reuses magic1 for file2

}

// Test to see if owner and friend can access after revoking someone.
func TestNotMyProblem(t *testing.T) {
	// Load Users A, B, C
	// User C creates a new 'fileC'
	// User B receives fileC from C
	// User A receives fileC from B
	// User C revokes fileC from User A
	// User C updates
	// User B receives update
}
*/
// Test

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
