package AsymmetricEncryption.DH;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;

//密钥交换算法
public class DHUtil {

    public static void main(String[] args) throws Exception {
        String data = "HanTongZi";
        jdkDH(data);
    }
    
    public static void jdkDH(String data) throws Exception {
        //1,初始化发送方秘钥
        KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        senderKeyPairGenerator.initialize(512);
        KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
        byte[] sendPublicKetEnc = senderKeyPair.getPublic().getEncoded();//发送方公钥,发送给接收方
        
        //2,初始化接收方秘钥
        KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(sendPublicKetEnc);
        PublicKey receiverPublickey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);
        DHParameterSpec dhParameterSpec =  ((DHPublicKey)receiverPublickey).getParams(); 
        KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        receiverKeyPairGenerator.initialize(dhParameterSpec);
        KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
        PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
        byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();
        
        //3,秘钥构建
        KeyAgreement receiveKeyAgreement = KeyAgreement.getInstance("DH");
        receiveKeyAgreement.init(receiverPrivateKey);
        receiveKeyAgreement.doPhase(receiverPublickey, true);
        SecretKey receiverDesKey = receiveKeyAgreement.generateSecret("DES");
        
        KeyFactory sendKeyFactory = KeyFactory.getInstance("DH");
        x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);
        PublicKey  senderPublicKey = sendKeyFactory.generatePublic(x509EncodedKeySpec);
        KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
        senderKeyAgreement.init(senderKeyPair.getPrivate());
        senderKeyAgreement.doPhase(senderPublicKey, true);
        
        SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
        
        if(Objects.equals(receiverDesKey, senderDesKey)) {
           System.out.println("双方秘钥相同"); 
        }
        
        //4,加密
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
        byte[] result = cipher.doFinal(data.getBytes());
        String dataEncrypt = Base64.encodeBase64String(result);
        System.out.println("JDK DH Encrypt:"+dataEncrypt);
        
        //5,解密
        cipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
        result = cipher.doFinal(result);
        String dataDecrypt = new String(result);
        System.out.println("JDK DH Decrypt:"+dataDecrypt);
    }
    

}
