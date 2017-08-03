package ntlm

import (
	rc4Std "crypto/rc4"
)

func rc4Encrypt(key []byte, ciphertext []byte) ([]byte, error) {
	cipher, err := rc4Std.NewCipher(key)
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(ciphertext))
	cipher.XORKeyStream(result, ciphertext)
	return result, nil
}
