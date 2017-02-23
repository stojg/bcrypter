package main

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
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

		passwordBytes, err := bcrypt.GenerateFromPassword([]byte(parts[1]), bcrypt.DefaultCost)
		if err != nil {
			return outData, err
		}
		outData[parts[0]] = string(passwordBytes)
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
