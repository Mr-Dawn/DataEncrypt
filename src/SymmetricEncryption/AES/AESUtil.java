package SymmetricEncryption.AES;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESUtil {
    
    public static void main(String[] args) throws Exception {
        String data = "HanTongZi";
        jdkAES(data);
    }
    
    public static void jdkAES(String data) throws Exception {
        //生成KEY
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(new SecureRandom());//初始化默认长度
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] keyBytas = secretKey.getEncoded();
        
        //KEY转换
        Key key = new SecretKeySpec(keyBytas, "AES");
        
        //加密
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] resultEncrypt = cipher.doFinal(data.getBytes());
        String AESEncrypt = Base64.encodeBase64String(resultEncrypt);
        System.out.println("JDK AES Encrypt:"+AESEncrypt);
        
        //解密
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] resultsDecrypt = cipher.doFinal(resultEncrypt);
        String AESDecrypt = new String(resultsDecrypt);
        System.out.println("JDK AES Decrypt:"+AESDecrypt);
    }
    
}
