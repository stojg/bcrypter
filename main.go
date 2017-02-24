package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s ./path-to-file\n", os.Args[0])
		os.Exit(0)
	}

	encrypted, err := encrypt(os.Args[1])
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	if err := store(os.Args[1], encrypted); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("File has been converted to a htpasswd file")
}

func encrypt(filePath string) (map[string]string, error) {
	outData := make(map[string]string)

	file, err := os.Open(filePath)
	if err != nil {
		return outData, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) != 2 {
			return outData, errors.New("in-data file must have the username and password separated with a space and each entry" +
				" needs to end with a newline")
		}
		for i, part := range parts {
			parts[i] = strings.Trim(part, " ")
		}
		if len(parts[1]) == 0 {
			return outData, errors.New("passwords must not be empty")
		}

		// the weird apache md5 hash format. :/ compatible with nginx
		hash, err := hashApr1Md5(parts[1])
		if err != nil {
			return outData, err
		}
		outData[parts[0]] = hash
	}

	if len(outData) == 0 {
		return outData, errors.New("No username/password pairs found in file")
	}
	return outData, nil
}

func store(filePath string, outData map[string]string) error {
	var fileContent []byte
	for username, password := range outData {
		fileContent = append(fileContent, []byte(fmt.Sprintf("%s:%s\n", username, password))...)
	}
	return ioutil.WriteFile(filePath, fileContent, 0600)
}

func hashSha(password string) (string, error) {
	s := sha1.New()
	s.Write([]byte(password))
	passwordSum := []byte(s.Sum(nil))
	return base64.StdEncoding.EncodeToString(passwordSum), nil
}

func hashBcrypt(password string) (hash string, err error) {
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	return string(passwordBytes), nil
}

// via https://github.com/tg123/go-htpasswd/blob/master/md5.go
func hashApr1Md5(password string) (string, error) {

	chars := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	var byteSalt []byte
	for i := 0; i < 8; i++ {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		byteSalt = append(byteSalt, chars[j.Int64()])
	}
	salt := string(byteSalt)

	// start with a hash of password and salt
	initBin := md5.Sum([]byte(password + salt + password))

	// begin an initial string with hash and salt
	initText := bytes.NewBufferString(password + "$apr1$" + salt)

	// add crap to the string willy-nilly
	for i := len(password); i > 0; i -= 16 {
		lim := i
		if lim > 16 {
			lim = 16
		}
		initText.Write(initBin[0:lim])
	}

	// add more crap to the string willy-nilly
	for i := len(password); i > 0; i >>= 1 {
		if (i & 1) == 1 {
			initText.WriteByte(byte(0))
		} else {
			initText.WriteByte(password[0])
		}
	}

	// Begin our hashing in earnest using our initial string
	bin := md5.Sum(initText.Bytes())

	n := bytes.NewBuffer([]byte{})

	for i := 0; i < 1000; i++ {
		// prepare to make a new muddle
		n.Reset()

		// alternate password+crap+bin with bin+crap+password
		if (i & 1) == 1 {
			n.WriteString(password)
		} else {
			n.Write(bin[:])
		}

		// usually add the salt, but not always
		if i%3 != 0 {
			n.WriteString(salt)
		}

		// usually add the password but not always
		if i%7 != 0 {
			n.WriteString(password)
		}

		// the back half of that alternation
		if (i & 1) == 1 {
			n.Write(bin[:])
		} else {
			n.WriteString(password)
		}

		// replace bin with the md5 of this muddle
		bin = md5.Sum(n.Bytes())
	}

	// At this point we stop transliterating the PHP code and flip back to
	// reading the Apache source. The PHP uses their base64 library, but that
	// uses the wrong character set so needs to be repaired afterwards and reversed
	// and it is just really weird to read.

	result := bytes.NewBuffer([]byte{})

	// This is our own little similar-to-base64-but-not-quite filler
	fill := func(a byte, b byte, c byte) {
		v := (uint(a) << 16) + (uint(b) << 8) + uint(c) // take our 24 input bits

		for i := 0; i < 4; i++ { // and pump out a character for each 6 bits
			result.WriteByte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[v&0x3f])
			v >>= 6
		}
	}

	// The order of these indices is strange, be careful
	fill(bin[0], bin[6], bin[12])
	fill(bin[1], bin[7], bin[13])
	fill(bin[2], bin[8], bin[14])
	fill(bin[3], bin[9], bin[15])
	fill(bin[4], bin[10], bin[5]) // 5?  Yes.
	fill(0, 0, bin[11])

	resultString := string(result.Bytes()[0:22]) // we wrote two extras since we only need 22.

	return fmt.Sprintf("$apr1$%s$%s", salt, resultString), nil
}
