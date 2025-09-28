<template>
  <div>
    <h1>ECDH Encryption Communication</h1>
    <form @submit.prevent="sendMessage">
      <div>
        <label for="message">Message:</label>
        <input type="text" v-model="message" id="message" />
      </div>
      <button type="submit">Send Encrypted Message</button>
    </form>
    <div v-if="receivedMessage">
      <h2>Received Decrypted Message:</h2>
      <p>{{ receivedMessage }}</p>
    </div>
  </div>
</template>

<script>
import CryptoJS from 'crypto-js';
import { generateKeyPair, calcSharedSecret } from '../utils/crypto.js';
import axios from 'axios';

export default {
  data() {
    return {
      message: '',
      receivedMessage: null,
      privateKey: null,
      publicKey: null,
      sharedSecret: null,
    };
  },
  created() {
    this.generateKeyPair();
  },
  methods: {
    generateKeyPair() {
      const keyPair = generateKeyPair();
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    },
    async sendMessage() {
      try {
        // 发送公钥到后端
        console.log("client.publicKey: " + this.publicKey);
        const response = await axios.post('/api/public-key', {
          publicKey: this.publicKey,
        });

        // 接收后端的公钥
        const serverPublicKey = response.data.publicKey;
        console.log("serverPublicKey: " + serverPublicKey);

        // 计算共享密钥
        const sharedSecret = calcSharedSecret(this.privateKey, serverPublicKey);
        console.log("ecdh sharedSecret: " + sharedSecret);

        // const x = aseEncrypt(this.message, PaddingLeft(sharedSecret, 16))
        // console.log("x: " + x)

        this.sharedSecret = sharedSecret;

        // 使用共享密钥加密消息
        // 此处默认使用cbc, pkcs7填充
        // sharedSecret长度是64字节，也就是256位，此处使用aes-256-cbc加密
        // sharedSecret长度是64字节，不属于AES加密的支持密钥长度。
        // aes加密支持16字节（128位）、24字节（192位）和32字节（256位）的密钥长度

        const encryptedMessage = CryptoJS.AES.encrypt(this.message, sharedSecret, {
          mode: CryptoJS.mode.CBC, // CBC算法
          padding: CryptoJS.pad.Pkcs7, //使用pkcs7 进行padding 后端需要注意
        });
        // 发送加密消息到后端
        const encryptedResponse = await axios.post('/api/encrypted-message', encryptedMessage.toString(), {
          headers: { 'Content-Type': 'text/plain' },
        });

        console.log("response message: ", encryptedResponse.data);
        const decryptedResponse = CryptoJS.AES.decrypt(encryptedResponse.data, sharedSecret, {
          mode: CryptoJS.mode.CBC, // CBC算法
          padding: CryptoJS.pad.Pkcs7, //使用pkcs7 进行padding 后端需要注意
        })

        // 接收后端解密后的消息
        this.receivedMessage = decryptedResponse.toString(CryptoJS.enc.Utf8);
        console.log(decryptedResponse.toString(CryptoJS.enc.Utf8));
      } catch (error) {
        console.error('Error:', error);
      }
    },
  },
};



</script>
