package SymmetricEncryption.DES;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;

public class DESUtil3 {
    
    public static void main(String[] args) throws Exception {
        String data = "HanTongZi";
        jdk3DES(data);
    }
    
    public static void jdk3DES(String data) throws Exception{
        //生成KEY
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
//        keyGenerator.init(168);
        keyGenerator.init(new SecureRandom());//生成默认长度
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] bytesKey = secretKey.getEncoded();
        
        //KEY转换
        DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
        Key  convertSecretKey = factory.generateSecret(desKeySpec);
        
        //加密
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
        byte[] result = cipher.doFinal(data.getBytes());
        
        String dataEncrypt =  Hex.encodeHexString(result);
        System.out.println("JDK 3DES Encrypt:"+dataEncrypt);
        //解密
        cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
        result= cipher.doFinal(result);
        String dataDecrypt = new String(result);
        System.out.println("JDK 3DES Decrypt:"+ dataDecrypt);
    }
    
}
