package SymmetricEncryption.DES;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Hex;

public class DESUtil {
        
    public static void main(String[] args) throws Exception {
        //测试
        String src = "HanTongZi";
        jdkDES(src);
    }
    
    public static void jdkDES(String data) throws Exception{
        //生成KEY
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] bytesKey = secretKey.getEncoded();
        
        //KEY转换
        DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        Key  convertSecretKey = factory.generateSecret(desKeySpec);
        
        //加密
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
        byte[] result = cipher.doFinal(data.getBytes());
        
        String dataEncrypt =  Hex.encodeHexString(result);
        System.out.println("JDK DES Encrypt:"+dataEncrypt);
        //解密
        cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
        result= cipher.doFinal(result);
        String dataDecrypt = new String(result);
        System.out.println("JDK DES Decrypt:"+ dataDecrypt);
    }
    
}
