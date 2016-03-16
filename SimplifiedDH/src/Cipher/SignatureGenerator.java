package Cipher;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by carlosmorais on 10/03/16.
 */
public class SignatureGenerator {
    public static final int KEY_LENGTH = 1024;

    //TODO File read/write with Java8 ?

    public static void generate(String filename){
        try {
            // Generate KeyPair
            KeyPairGenerator keyPG = KeyPairGenerator.getInstance("RSA");
            keyPG.initialize(KEY_LENGTH , new SecureRandom());
            KeyPair keyPair = keyPG.generateKeyPair();

            // Write Public Key
            X509EncodedKeySpec pk = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
            FileOutputStream pkFOS = new FileOutputStream(filename + ".pkey");
            pkFOS.write(pk.getEncoded());
            pkFOS.close();

            // Write Secret Key
            PKCS8EncodedKeySpec sk = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            FileOutputStream skFOS = new FileOutputStream(filename + ".skey");
            skFOS.write(sk.getEncoded());
            skFOS.close();

            //log("pk: "+ Base64.getEncoder().encodeToString( keyPair.getPublic().getEncoded()));
            //log("sk: "+ Base64.getEncoder().encodeToString( keyPair.getPrivate().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static KeyPair load(String filename){
        try {
            // Read Public Key
            FileInputStream pkFIS = new FileInputStream(filename + ".pkey");
            byte[] pkBuffer = new byte[KEY_LENGTH];
            pkFIS.read(pkBuffer);
            pkFIS.close();

            // Read Secret Key
            FileInputStream skFIS = new FileInputStream(filename + ".skey");
            byte[] skBuffer = new byte[KEY_LENGTH];
            skFIS.read(skBuffer);
            skFIS.close();

            // Generate KeyPair
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    pkBuffer);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                    skBuffer);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            //log("pk: "+ Base64.getEncoder().encodeToString( privateKey.getEncoded()));
            //log("sk: "+ Base64.getEncoder().encodeToString( publicKey.getEncoded()));
            return new KeyPair(publicKey, privateKey);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void log(String s){
        System.out.println(s);
    }

    public static void main(String[] args){
        generate("server");
        generate("client");
    }
}
