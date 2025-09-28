package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/miaoyc666/goArsenal/crypto/aes"
	"github.com/miaoyc666/goArsenal/crypto/ecdsa"
)

type CryptoHandler struct {
	KeyManager *ecdsa.KeyManager
}

func NewCryptoHandler(km *ecdsa.KeyManager) *CryptoHandler {
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
	sharedSecretHex := ch.KeyManager.CalcSharedSecret()
	fmt.Println("sharedSecretHex: ", sharedSecretHex)

	// 解码base64密文
	ciphertext, err := base64.StdEncoding.DecodeString(textData)
	if err != nil {
		ch.logAndError(w, "Failed to decode base64", http.StatusBadRequest)
		return
	}

	// 使用CryptoJS兼容的解密方法
	messageBytes, err := aes.CryptoJsCbcDecrypt(ciphertext, sharedSecretHex)
	if err != nil {
		fmt.Println("decryptMessage error: ", string(messageBytes), err)
		ch.logAndError(w, "Error decrypting message", http.StatusInternalServerError)
		return
	}
	message := string(messageBytes)
	fmt.Println("receive message: ", message)

	respStr := "hello " + message

	// 使用CryptoJS兼容的加密方法
	encryptedBytes, err := aes.CryptoJsCbcEncrypt([]byte(respStr), sharedSecretHex)
	if err != nil {
		log.Println("Error encrypting message:", err)
		ch.logAndError(w, "Error encrypting message", http.StatusInternalServerError)
		return
	}

	// 转换为base64
	encode := base64.StdEncoding.EncodeToString(encryptedBytes)
	fmt.Println("encode: ", encode)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(encode))
}

func main() {
	keyManager, err := ecdsa.NewKeyManager()
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
