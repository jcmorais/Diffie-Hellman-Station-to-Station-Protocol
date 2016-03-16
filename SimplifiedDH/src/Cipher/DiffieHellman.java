package Cipher;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Created by carlosmorais on 08/03/16.
 */
public class DiffieHellman {
    public static final int PRIME_LENGTH = 1024; //bits
    private static final int IV_LENGTH = 16; //bits
    private static final int HMAC_LENGTH = 32; //bytes

    private SecretKey sharedKey;
    private SecureRandom random;
    public byte[] iv;

    public DiffieHellman() {
        this.random = new SecureRandom();
        this.iv = new byte[IV_LENGTH];
    }

    public void startDHagreement(BufferedReader in, PrintWriter out){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");

            BigInteger primeModules = this.generateBigPrime(PRIME_LENGTH);
            BigInteger generator = this.generateBigPrime(PRIME_LENGTH);
            this.random.nextBytes(this.iv);

            DHParameterSpec dhPS = new DHParameterSpec(primeModules, generator);
            keyPairGen.initialize(dhPS, this.random);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // send @generator, @primeModules, @publicKey and @iv to Client
            out.println(generator);
            out.println(primeModules);
            out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            out.println(Base64.getEncoder().encodeToString(this.iv));
            out.flush();

            //receive @publicKey from Client
            byte[] pkBytes = Base64.getDecoder().decode(in.readLine());
            X509EncodedKeySpec ks = new X509EncodedKeySpec(pkBytes);
            PublicKey pkClient = keyFactory.generatePublic(ks);

            //compute @sharedKey
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(pkClient, true);
            this.sharedKey = keyAgree.generateSecret("AES");

            // read keyPair Sign
            KeyPair keyPairRSA = SignatureGenerator.load("server");
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initSign(keyPairRSA.getPrivate());
            keyFactory = KeyFactory.getInstance("RSA");

            //send publicKeySign to client
            out.println(Base64.getEncoder().encodeToString(
                    new X509EncodedKeySpec(keyPairRSA.getPublic().getEncoded()).getEncoded()) );
            out.flush();

            //read client publicKeySign
            PublicKey pkSignClient = keyFactory.generatePublic(
                    new X509EncodedKeySpec(
                            Base64.getDecoder().decode(
                                    in.readLine())));

            // receice Client signature
            byte[] signClient = this.decrypt(Base64.getDecoder().decode(in.readLine()));

            sign.update(keyPair.getPublic().getEncoded());
            sign.update(pkClient.getEncoded());

            // send signature to Client
            out.println(Base64.getEncoder().encodeToString(this.encrypt(sign.sign())));
            out.flush();

            // verify the signature
            Signature clientSign = Signature.getInstance("SHA1withRSA");
            clientSign.initVerify(pkSignClient);
            clientSign.update(pkClient.getEncoded());
            clientSign.update(keyPair.getPublic().getEncoded());

            if(!clientSign.verify(signClient))
                throw new DHException("Invalid Signature!\n");
            else
                log("validated STS");

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (DHException e) {
            e.printStackTrace();
        }
    }


    public void proceedDHagreement(BufferedReader in, PrintWriter out){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");

            // receive @generator, @primeModules, @publicKey and @iv from Server
            BigInteger generator = new BigInteger(String.valueOf(in.readLine()));
            BigInteger primeModules = new BigInteger(String.valueOf(in.readLine()));
            byte[] publicKey = Base64.getDecoder().decode(in.readLine());
            this.iv = Base64.getDecoder().decode(in.readLine());

            DHParameterSpec dhPS = new DHParameterSpec(primeModules, generator);
            keyPairGen.initialize(dhPS, new SecureRandom());
            KeyPair keyPair = keyPairGen.generateKeyPair();

            X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKey);
            PublicKey pkServer = keyFactory.generatePublic(ks);

            // send @publicKey to Client
            out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            out.flush();

            // compute @sharedKey
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(pkServer, true);
            this.sharedKey = keyAgree.generateSecret("AES");

            //**************************//

            // read keyPair Sign
            KeyPair keyPairRSA = SignatureGenerator.load("client");
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initSign(keyPairRSA.getPrivate());
            keyFactory = KeyFactory.getInstance("RSA");

            // send publicKeySign to Server
            out.println(Base64.getEncoder().encodeToString(
                    new X509EncodedKeySpec(keyPairRSA.getPublic().getEncoded()).getEncoded()) );
            out.flush();

            // read Server publicKeySign
            PublicKey pkSignServer = keyFactory.generatePublic(
                    new X509EncodedKeySpec(
                            Base64.getDecoder().decode(
                                    in.readLine())));

            sign.update(keyPair.getPublic().getEncoded());
            sign.update(pkServer.getEncoded());

            // send signature to Server
            out.println(Base64.getEncoder().encodeToString(this.encrypt(sign.sign())));
            out.flush();

            // receice Server signature
            byte[] aux = Base64.getDecoder().decode(in.readLine());
            byte[] signServer = this.decrypt(aux);


            // verify the signature
            Signature serverSign = Signature.getInstance("SHA1withRSA");
            serverSign.initVerify(pkSignServer);
            serverSign.update(pkServer.getEncoded());
            serverSign.update(keyPair.getPublic().getEncoded());

            if(!serverSign.verify(signServer))
                throw new DHException("Invalid Signature!\n");
            else
                log("validated STS");

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (DHException e) {
            e.printStackTrace();
        }
    }


    //TODO sharedKey pode ser usada como chave para a cifra e o mac???
    public byte[] encrypt(byte[] message){
        byte[] cryptogram = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, this.sharedKey , new IvParameterSpec(iv));

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(this.sharedKey);

            byte[] cipherText = cipher.doFinal(message);
            byte[] hMac = mac.doFinal(cipherText);

            cryptogram = new byte[cipherText.length + HMAC_LENGTH];
            System.arraycopy(hMac, 0, cryptogram, 0, HMAC_LENGTH);
            System.arraycopy(cipherText, 0, cryptogram, HMAC_LENGTH, cipherText.length);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return cryptogram;
    }


    public byte[] decrypt(byte[] message) throws DHException {
        byte[] plainText = null;
        try {
            byte[] hMac = Arrays.copyOfRange(message, 0, HMAC_LENGTH);
            byte[] cipherText = Arrays.copyOfRange(message, HMAC_LENGTH, message.length);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(this.sharedKey);
            byte[] hMac2 = mac.doFinal(cipherText);

            if (MessageDigest.isEqual(hMac, hMac2)) {
                Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, this.sharedKey, new IvParameterSpec(iv));
                plainText = cipher.doFinal(cipherText);
            }
            else
                throw new DHException("Problem: intrusion attempt!");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return plainText;
    }

    //método para testes...
    private void log(String s){
        System.out.println(s);
    }

    //não é garantido que o número seja realmente um primo, mas é MUITO provavel...
    private BigInteger generateBigPrime(int bits) {
        return BigInteger.probablePrime(bits, random);
    }
}
