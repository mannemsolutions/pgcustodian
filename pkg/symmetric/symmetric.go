package symmetric

/*

 */
import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// PasswordToKey can be used to convert a password (string) into a byte sequence using sha256
func PasswordToKey(password string, size AESKeySize) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	return h.Sum(nil)[:size]
}

// StreamEncrypt can be used to encrypt data from a stream and write output to a stream.
// Usually StreamEncrypt is run through the EncryptStdinToFile and similar functions
func StreamEncrypt(key []byte, input *bufio.Reader, output *bufio.Writer) (int64, error) {
	var written int64
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("error getting cipher block: %w", err)
	}
	// Make a unique iv
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return 0, fmt.Errorf("error generating iv: %w", err)
	}

	if ivWritten, err := output.Write(iv); err != nil {
		return int64(ivWritten), fmt.Errorf("error writing iv: %w", err)
	} else {
		written += int64(ivWritten)
	}

	stream := cipher.NewCTR(block, iv[:])

	reader := &cipher.StreamReader{S: stream, R: input}

	// Copy the input to the output stream, decrypting as we go.
	if streamWritten, err := io.Copy(output, reader); err != nil {
		written += streamWritten
		return written, fmt.Errorf("error encrypting data: %w", err)
	} else if written != aes.BlockSize {
		panic(fmt.Errorf("expected %d, got %d", aes.BlockSize, len(iv)))
	} else {
		written += streamWritten
		return written, nil
	}
}

func EncryptToFile(key []byte, input *bufio.Reader, outFile string) (int64, error) {
	out, err := os.Create(outFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open output file %s: %w", outFile, err)
	}
	defer func() {
		cErr := out.Close()
		if err == nil {
			err = cErr
		}
	}()
	buffer := bufio.NewWriter(out)
	defer buffer.Flush()

	return StreamEncrypt(key, input, buffer)
}

// StreamDecrypt can be used to encrypt data from a stream and write output to a stream.
// Usually StreamDecrypt is run through the DecryptFileToStdout and similar functions
func StreamDecrypt(key []byte, input *bufio.Reader, output *bufio.Writer) (int64, error) {
	var read int64
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("error getting cipher: %w", err)
	}
	// Read iv from input
	iv := make([]byte, aes.BlockSize)
	if ivRead, err := io.ReadFull(input, iv); err != nil {
		read += int64(ivRead)
		return read, fmt.Errorf("error getting iv: %w", err)
	} else {
		read += int64(ivRead)
	}
	stream := cipher.NewCTR(block, iv[:])

	reader := &cipher.StreamReader{S: stream, R: input}
	// Copy the input to the output stream, decrypting as we go.
	if decryptedRead, err := io.Copy(output, reader); err != nil {
		read += decryptedRead
		return read, fmt.Errorf("error while decrypting data: %w", err)
	} else {
		read += decryptedRead
		return read, nil
	}
}

func Cycle(oldKey []byte, inFile string, newKey []byte, outFile string) error {
	buffer := bytes.NewBuffer([]byte{})
	type returnValues struct {
		count int64
		err   error
	}
	c := make(chan returnValues)

	go func() {
		count, err := EncryptToFile(newKey, bufio.NewReader(buffer), outFile)
		c <- returnValues{count, err}
	}()

	count, err := DecryptFromFile(oldKey, inFile, bufio.NewWriter(buffer))
	if err != nil {
		return fmt.Errorf("error while decrypting: %w", err)
	}
	encryptResults := <-c
	if encryptResults.err != nil {
		return fmt.Errorf("error while encrypting: %w", err)
	}
	if count != encryptResults.count {
		return fmt.Errorf("%d was decrypted, but %d was encrypted", count, encryptResults.count)
	}

	return nil
}

func DecryptFromFile(key []byte, inFile string, output *bufio.Writer) (int64, error) {
	in, err := os.Open(inFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open input file %s: %w", inFile, err)
	}
	defer func() {
		cErr := in.Close()
		if err == nil {
			err = cErr
		}
	}()

	return StreamDecrypt(key, bufio.NewReader(in), output)
}
