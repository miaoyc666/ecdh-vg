import CryptoJS from 'crypto-js'
import {Buffer} from 'buffer'
import {secp256k1} from 'ethereum-cryptography/secp256k1'
import {getRandomBytesSync} from 'ethereum-cryptography/random'

export const generateKeyPair = () => {
  const privateKey = getRandomBytesSync(32) // 32字节随机数
  const privateKeyHex = Buffer.from(privateKey).toString('hex')

  // 获取公钥（未压缩 65字节，压缩33字节可传true）
  const publicKey = secp256k1.getPublicKey(privateKey, false) // false = 未压缩格式
  const publicKeyHex = Buffer.from(publicKey).toString('hex')

  return { privateKey: privateKeyHex, publicKey: publicKeyHex }
}

export const calcSharedSecret = (privateKey, publicKey) => {
  // 将十六进制字符串转换为 Uint8Array
  const privateKeyBytes = new Uint8Array(Buffer.from(privateKey, 'hex'))
  const publicKeyBytes = new Uint8Array(Buffer.from(publicKey, 'hex'))

  // 使用 secp256k1.getSharedSecret 计算共享密钥
  const sharedSecretBytes = secp256k1.getSharedSecret(privateKeyBytes, publicKeyBytes)

  // ethereum-cryptography 返回的是33字节的共享密钥（包含前缀），我们需要取后32字节
  // 或者直接使用前32字节作为共享密钥
  const sharedSecretKey = sharedSecretBytes.slice(1) // 去掉第一个字节（压缩标识）

  // 转换为十六进制字符串并确保长度为64
  let sharedSecret = Buffer.from(sharedSecretKey).toString('hex')

  // 补全前导零以确保字符串长度为64
  while (sharedSecret.length < 64) {
    sharedSecret = '0' + sharedSecret
  }

  return sharedSecret
}

// cbc加密，加密位数取决于密钥长度，加密后会对密文进行base64编码
const aesCbcEncrypt = (message, sharedSecret) => {
  const encryptedMessage = CryptoJS.AES.encrypt(message, sharedSecret, {
    mode: CryptoJS.mode.CBC, // CBC算法
    padding: CryptoJS.pad.Pkcs7, // 使用pkcs7 进行padding
  })
  return encryptedMessage.toString()
}

const aesCbcDecrypt = (message, sharedSecret) => {
  const decryptedResponse = CryptoJS.AES.decrypt(message, sharedSecret, {
    mode: CryptoJS.mode.CBC, // CBC算法
    padding: CryptoJS.pad.Pkcs7, // 使用pkcs7 进行padding
  })
  return decryptedResponse.toString(CryptoJS.enc.Utf8)
}

// 数据加密函数
export function encryptData(privateKey, publicKey, data) {
  const sharedSecret = calcSharedSecret(privateKey, publicKey)
  const message = JSON.stringify(data)
  return aesCbcEncrypt(message, sharedSecret)
}

// 数据解密函数
export function decryptData(privateKey, publicKey, data) {
  const sharedSecret = calcSharedSecret(privateKey, publicKey)
  return aesCbcDecrypt(data, sharedSecret)
}
