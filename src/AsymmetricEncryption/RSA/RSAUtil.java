package AsymmetricEncryption.RSA;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
//因子分解算法
public class RSAUtil {
    
    public static void main(String[] args) throws Exception {
        String data = "HanTongZi";
        jdkRSA(data);
    }
    
    public static void jdkRSA(String data) throws Exception {
        //1.初始化秘钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair=keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
        String publicKeyStr = Base64.encodeBase64String(rsaPublicKey.getEncoded());//公钥
        String privateKeyStr = Base64.encodeBase64String(rsaPrivateKey.getEncoded());//私钥
        System.out.println("Public Key :"+ publicKeyStr);
        System.out.println("Private Key :"+ privateKeyStr);
        
        //2.私钥加密,公钥解密----加密
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(data.getBytes());
        System.out.println("私钥加密,公钥解密----加密"+Base64.encodeBase64String(result));
        
        //3.私钥加密,公钥解密----解密
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        result = cipher.doFinal(result);
        System.out.println("私钥加密,公钥解密----解密"+new String(result));
        
        //4.公钥加密,私钥解密----加密
        x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        result = cipher.doFinal(data.getBytes());
        System.out.println("公钥加密,私钥解密----加密"+Base64.encodeBase64String(result));
        
        //5.公钥加密,私钥解密----解密
        new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        result = cipher.doFinal(result);
        System.out.println("公钥加密,私钥解密----解密"+new String(result));
    }
}
