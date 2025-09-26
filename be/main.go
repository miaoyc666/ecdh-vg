package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/mux"
)

type KeyManager struct {
	ServerPrivateKey *ecdsa.PrivateKey
	ClientPublicKey  *ecdsa.PublicKey
}

func NewKeyManager() (*KeyManager, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyManager{ServerPrivateKey: privateKey}, nil
}

func (km *KeyManager) SetClientPublicKey(hexKey string) error {
	clientPublicKeyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return err
	}
	clientPublicKey, err := crypto.UnmarshalPubkey(clientPublicKeyBytes)
	if err != nil {
		return err
	}
	km.ClientPublicKey = clientPublicKey
	return nil
}

func (km *KeyManager) GetServerPublicKeyHex() string {
	serverPublicKeyBytes := crypto.FromECDSAPub(&km.ServerPrivateKey.PublicKey)
	return hex.EncodeToString(serverPublicKeyBytes)
}

func (km *KeyManager) ComputeSharedSecret() ([]byte, error) {
	fmt.Println("client public key hex:", hex.EncodeToString(crypto.FromECDSAPub(km.ClientPublicKey)))
	sharedX, _ := km.ServerPrivateKey.PublicKey.Curve.ScalarMult(km.ClientPublicKey.X, km.ClientPublicKey.Y, km.ServerPrivateKey.D.Bytes())
	return sharedX.Bytes(), nil
}

type CryptoHandler struct {
	KeyManager *KeyManager
}

func NewCryptoHandler(km *KeyManager) *CryptoHandler {
	return &CryptoHandler{KeyManager: km}
}

func (ch *CryptoHandler) logAndError(w http.ResponseWriter, message string, statusCode int) {
	log.Println(message)
	http.Error(w, message, statusCode)
}

func (ch *CryptoHandler) HandlePublicKey(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		ch.logAndError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := ch.KeyManager.SetClientPublicKey(requestBody.PublicKey); err != nil {
		ch.logAndError(w, "Failed to set client public key", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"publicKey": ch.KeyManager.GetServerPublicKeyHex(),
	})
}

func (ch *CryptoHandler) HandleEncryptedMessage(w http.ResponseWriter, r *http.Request) {
	// 读取请求体中的文本数据
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		// 如果读取出错，返回错误信息
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	// 将读取到的文本数据转换为字符串
	textData := string(body)

	fmt.Println("requestBody base64:", textData)
	sharedSecret, err := ch.KeyManager.ComputeSharedSecret()
	sharedSecretHex := hex.EncodeToString(sharedSecret)
	fmt.Println("sharedSecretHex: ", sharedSecretHex)
	if err != nil {
		ch.logAndError(w, "Failed to compute shared secret", http.StatusInternalServerError)
		return
	}
	message, err := AES256Decode(textData, sharedSecretHex)
	if err != nil {
		fmt.Println("decryptMessage error: ", message, err)
		return
	}
	fmt.Println("receive message: ", message)

	respStr := "hello " + message
	encode, err := AES256Encode(respStr, sharedSecretHex)
	fmt.Println("encode: ", encode)
	if err != nil {
		log.Println("Error decrypting message:", err)
		http.Error(w, "Error decrypting message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(encode))
}

func getIVAndKey(ciphertext []byte, key string) (iv []byte, calKey []byte) {
	salt := ciphertext[8:16]
	fmt.Println("salt: ", salt)
	fmt.Println("source key: ", key)
	hash1 := md5.Sum([]byte(key + string(salt)))
	hash2 := md5.Sum(append(hash1[:], []byte(key+string(salt))...))
	hash3 := md5.Sum(append(hash2[:], []byte(key+string(salt))...))
	calKey = append(hash1[:], hash2[:]...)
	iv = hash3[:]
	return
}

const (
	saltSize = 8
	prefix   = "Salted__"
)

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func genKeyAndIV(salt []byte, key string) (iv, calKey []byte) {
	fmt.Println("salt: ", salt)
	fmt.Println("source key: ", key)
	hash1 := md5.Sum([]byte(key + string(salt)))
	hash2 := md5.Sum(append(hash1[:], []byte(key+string(salt))...))
	hash3 := md5.Sum(append(hash2[:], []byte(key+string(salt))...))
	calKey = append(hash1[:], hash2[:]...)
	iv = hash3[:]
	return
}

// pkcs7Pad 对数据进行PKCS7填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func AES256Encode(plaintext string, password string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	iv, calKey := genKeyAndIV(salt, password)
	block, err := aes.NewCipher(calKey)
	if err != nil {
		return "", err
	}

	plaintextBytes := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(plaintextBytes))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintextBytes)

	finalCiphertext := append([]byte(prefix), salt...)
	finalCiphertext = append(finalCiphertext, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalCiphertext), nil
}

func AES256Decode(encodeStr string, key string) (string, error) {
	// base64Decode
	ciphertext, err := base64.StdEncoding.DecodeString(encodeStr)
	if err != nil {
		return "", err
	}
	//
	iv, calKey := getIVAndKey(ciphertext, key)
	block, err := aes.NewCipher(calKey)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	// 去除前缀与salt
	ciphertext = ciphertext[16:]
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 去除填充, PKCS7UnPadding
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen > len(plaintext) {
		return "", errors.New("padding len error")
	}

	return string(plaintext[:len(plaintext)-paddingLen]), nil
}

func main() {
	keyManager, err := NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize key manager: %v", err)
	}

	cryptoHandler := NewCryptoHandler(keyManager)

	r := mux.NewRouter()
	r.HandleFunc("/public-key", cryptoHandler.HandlePublicKey).Methods("POST")
	r.HandleFunc("/encrypted-message", cryptoHandler.HandleEncryptedMessage).Methods("POST")

	fmt.Println("Server is running on port 8081")
	log.Fatal(http.ListenAndServe(":8081", r))
}
