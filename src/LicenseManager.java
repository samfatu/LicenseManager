import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class LicenseManager {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private byte[] clientEncryptedInfo;

    public LicenseManager(byte[] clientEncryptedInfo) throws Exception {
        System.out.println("LicenseManager service started...");
        this.clientEncryptedInfo = clientEncryptedInfo;

        byte[] publicKeyFile = Client.readFileAsByteArray("public.key");
        byte[] privateKeyFile = Client.readFileAsByteArray("private.key");

        this.publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyFile));
        this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyFile));
    }

    public byte[] getSignature() throws Exception {
        System.out.println("Server - Server is being requested...");
        System.out.println("Server - Incoming Encrypted Text: " +  Base64.getEncoder().encodeToString(clientEncryptedInfo));
        byte[] decryptedData = this.decrypt(this.clientEncryptedInfo);
        System.out.println("Server - Decrypted Text: " + (new String(decryptedData, StandardCharsets.UTF_8)));
        byte[] hashedData = this.hash(decryptedData);
        System.out.println("Server - MD5 Plain License Text: " + Client.byteArrayToHexString(hashedData));
        byte[] signedData = this.encrypt(hashedData);
        System.out.println("Server - Digital Signature: " + Base64.getEncoder().encodeToString(signedData));

        return signedData;
    }

    private byte[] encrypt(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private byte[] decrypt(byte[] encryptedData) throws Exception {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, this.privateKey);

        return decryptCipher.doFinal(encryptedData);
    }

    private byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data);
        return md.digest();
    }

}
