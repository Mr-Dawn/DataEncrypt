package SymmetricEncryption.PDE;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class PBEUtil {
    
    public static void main(String[] args) throws Exception {
        
        String data = "HanTongZi";
        jdkPBE(data);
    }
    
    public static void jdkPBE(String data) throws Exception {
        //初始化 盐(salt)
        SecureRandom random = new SecureRandom();
        byte[] salt = random.generateSeed(8);
        
        //口令与秘钥
        String password = "MaLuoTong";//密码
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
        Key key = factory.generateSecret(keySpec);
        
        //加密
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, 100);
        Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] result = cipher.doFinal(data.getBytes());
        String PBEEncrypt = Base64.encodeBase64String(result);
        System.out.println("JDK PBE Encrypt:"+PBEEncrypt);
        
        //解密
        cipher.init(Cipher.DECRYPT_MODE, key,parameterSpec);
        result = cipher.doFinal(result);
        String PBEDecrypt = new String(result);
        System.out.println("JDK PBE Decrypt:"+PBEDecrypt);
        
    }
}
