package AsymmetricEncryption.ElGamal;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//离散对数算法
public class ElGamalUtil {

    public static void main(String[] args) throws Exception {
        String data = "{\r\n" + 
                "            \"name\": \"Google\",\r\n" + 
                "            \"url\": \"http://www.google.com\"\r\n" + 
                "        },\r\n" + 
                "        {\r\n" + 
                "            \"name\": \"Baidu\",\r\n" + 
                "            \"url\": \"http://www.baidu.com\"\r\n" + 
                "        },\r\n" + 
                "        {\r\n" + 
                "            \"name\": \"SoSo\",\r\n" + 
                "            \"url\": \"http://www.SoSo.com\"\r\n" + 
                "        }";
        jdkElGamal(data);
    }
    
    public static void jdkElGamal(String data) throws Exception {
        //公钥加密,私钥解密
        Security.addProvider(new BouncyCastleProvider()); 
        
        //1.初始化秘钥
        AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
        algorithmParameterGenerator.init(128);
        AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters(); 
        DHParameterSpec dhParameterSpec = (DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
        keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey elGamalPublicKey = keyPair.getPublic();
        PrivateKey elGamalPrivateKey = keyPair.getPrivate();
        System.out.println("Public Key:"+ Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
        System.out.println("Private Key:"+ Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));
        
        //2.公钥加密,私钥解密----加密
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("ElGamal");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(data.getBytes());
        System.out.println("公钥加密,私钥解密----加密"+Base64.encodeBase64String(result));
        
        //3.公钥加密,私钥解密----解密
        PKCS8EncodedKeySpec  pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
        keyFactory = KeyFactory.getInstance("ElGamal");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        cipher = Cipher.getInstance("ElGamal");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        result = cipher.doFinal(result);
        System.out.println("公钥加密,私钥解密----解密"+new String(result));
    }

}
