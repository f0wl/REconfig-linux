package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/fatih/color"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func scanFile(data []byte, search []byte) (int, error) {
	return bytes.Index(data, search), nil
}

func calcSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func calcMD5(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

var (
	verboseFlag bool
)

func main() {

	fmt.Printf("\n\n  ####  ##### #   #  ###  #   #   #   #   # #####     ##### #   # #   # #   # #   #  \n")
	fmt.Printf("  #   # #     #   # #   # #   #  ###  #  ## #   #      #  # #  ## #   #  # #  # # #  \n")
	fmt.Printf("  ####  ####   #### #   # ##### # # # # # # #     ###  #  # # # # #####   #   # # #  \n")
	fmt.Printf("  #     #         # #   # #   #  ###  ##  # #          #  # ##  # #   #  #    # # #  \n")
	fmt.Printf("  #     #####     #  ###  #   #   #   #   # #         #   # #   # #   # #      ##### \n")
	fmt.Printf("  REconfig-linux\n\n")
	fmt.Printf("  REvil Linux Ransomware Configuration Extractor\n")
	fmt.Printf("  Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	// parse passed flags
	flag.BoolVar(&verboseFlag, "print", false, "Print config to stdout")
	flag.Parse()
	if flag.NArg() == 0 {
		color.Red("✗ No path to sample provided.\n\n")
		os.Exit(1)
	}

	f, openErr := os.Open(flag.Args()[0])
	check(openErr)
	defer f.Close()

	readseeker := io.ReadSeeker(f)
	malwareData, readErr := ioutil.ReadAll(readseeker)
	check(readErr)

	// check if the specified file is an ELF file or not
	elfMagic := "7F454C46"
	elfBytes, byteErr := hex.DecodeString(elfMagic)
	check(byteErr)
	elfOffset, scanErr := scanFile(malwareData, elfBytes)
	check(scanErr)

	if elfOffset == -1 {
		fmt.Printf("✗ The specified file is not an ELF file. Windows PE samples are not supported.\n\n")
		os.Exit(1)
	}

	fmt.Printf("→ Sample SHA-256: %v\n", hex.EncodeToString(calcSHA256(malwareData)))

	// search for the pattern: {"pk":"
	offsetPattern := "7B22706B223A22"
	patternBytes, bytesErr := hex.DecodeString(offsetPattern)
	check(bytesErr)
	offset, scanErr := scanFile(malwareData, patternBytes)
	check(scanErr)

	if offset != -1 {
		fmt.Printf("✓ Found the json config string.\n\n")
	} else {
		fmt.Printf("✗ Unable to find the json config string.\n\n")
		os.Exit(1)
	}

	// read from the file and trim superfluous nullbytes at the end
	extractedConfig := malwareData[offset : offset+3072]
	extractedConfig = bytes.Trim(extractedConfig, "\x00")

	// beautify the json string
	var outBuf bytes.Buffer
	jsonErr := json.Indent(&outBuf, extractedConfig, "", "  ")
	check(jsonErr)

	if verboseFlag {
		color.Green("✓ Beautified JSON config:\n\n")
		fmt.Printf("%v\n\n", outBuf.String())
	} else {
		// Write json config to a file
		configFilename := "config-" + hex.EncodeToString(calcMD5(malwareData)) + ".json"
		writeErr := ioutil.WriteFile(configFilename, outBuf.Bytes(), 0644)
		check(writeErr)
		color.Green("✓ Wrote extracted config to '%s'\n", configFilename)
	}

	// and now for some fancy Golang magic :D Extracting the Ransomnote from the json string via an Interface
	// This saves a lot of time and is less prone to errors since we don't have to unmarshal into a structure
	// Declaring an empty interface
	var confInterf map[string]interface{}

	// unmarshal the json string into the interface
	json.Unmarshal([]byte(outBuf.String()), &confInterf)

	// extract the encoded ransomnote string
	ransomnote := confInterf["nbody"]
	// decode the note from base64, var ransomnote is type-asserted to string
	decodedNote, base64Err := base64.StdEncoding.DecodeString(ransomnote.(string))
	check(base64Err)

	if verboseFlag {
		color.Green("✓ Extracted and base64 decoded Ransomnote:\n\n")
		fmt.Printf(string(decodedNote) + "\n\n")
		os.Exit(0)
	} else {
		// Write decoded ransomnote text to a file
		ransomnoteFilename := "ransomnote-" + hex.EncodeToString(calcMD5(malwareData)) + ".txt"
		writeErr := ioutil.WriteFile(ransomnoteFilename, decodedNote, 0644)
		check(writeErr)
		color.Green("✓ Wrote decoded ransomnote to '%s'\n\n", ransomnoteFilename)
	}
}
