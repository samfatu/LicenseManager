import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Client {
    private static final String USERNAME = "RONALDO";
    private static final String SERIAL = "1234-5678-9123";
    private static final String MAC = "AB:23:4D:12";
    private static final String DISK_SERIAL = "-455469999";
    private static final String MOTHERBOARD_SERIAL = "201075710502043";
    private PublicKey publicKey;

    public Client() throws Exception {
        starterLogs();
        byte[] publicKeyFile = Client.readFileAsByteArray("public.key");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyFile));
    }

    public static void main(String[] args) throws Exception {
        Client client = new Client();

        String userSpecificInfo = client.getUserSpecificInfo();
        byte[] encryptedInfo = client.encrypt(userSpecificInfo);

        LicenseManager licenseManager = new LicenseManager(encryptedInfo);

        if (client.isLicenseFileExists()) {
            byte[] license = Client.readFileAsByteArray("license.txt");
            System.out.print("License is found and verification result is ");
            if (client.verifySignature(license)) {
                System.out.println("Client - Succeed. The license is correct.");
            } else {
                // todo: eğer burada re-ex yapılınca else içindekiler tekrar yapılıyorsa if ve else içlerini ayrı fonksiyonlara çek
                System.out.println("Client - The license file has been broken!!");
            }
        } else {
            System.out.println("Client - License file is not found!");
            System.out.println("Client - Raw License Text: " + client.getUserSpecificInfo());
            // TODO: Yiyo
            System.out.print("Client - Encrypted License Text: ");
            System.out.println((new String(encryptedInfo)));
            System.out.println("Client - MD5 License Text: " + DatatypeConverter.printHexBinary(
                    client.hash(client.getUserSpecificInfo().getBytes(StandardCharsets.UTF_8))));
            byte[] signature = licenseManager.getSignature();
            // TODO: alt satırı if else'e çek, key'in corrupted olup olmadığına bağlı
            System.out.println(client.verifySignature(signature));
            //Client.writeFile("license.txt", signature);
            System.out.println("Client - Succed");
        }

    }

    private String getUserSpecificInfo() {
        return USERNAME + "$" + SERIAL + "$" + MAC + "$" + DISK_SERIAL + "$" + MOTHERBOARD_SERIAL;
    }

    private byte[] encrypt(String data) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] secretMessageBytes = data.getBytes(StandardCharsets.UTF_8);

        return encryptCipher.doFinal(secretMessageBytes);
    }

    private Signature decrypt(byte[] encryptedData) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(encryptedData);
        return signature;
    }

    private byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data);
        return md.digest();
    }

    private boolean verifySignature(byte[] signature) throws Exception {
        byte[] hashedInfo = hash(getUserSpecificInfo().getBytes(StandardCharsets.UTF_8));
        return decrypt(hashedInfo).verify(signature);
    }

    private void starterLogs() {
        System.out.println("Client started...");
        System.out.println("My MAC: " + MAC);
        System.out.println("My Disk ID: " + DISK_SERIAL);
        System.out.println("My Motherboard ID: " + MOTHERBOARD_SERIAL);
    }

    public boolean isLicenseFileExists() {
        File licenseFile = new File("license.txt");
        return licenseFile.exists();
    }

    public static byte[] readFileAsByteArray(String filePath) {
        File file = new File(filePath);
        byte[] content = null;
        try {
            content = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    public static void writeFile(String outputFilePath, byte[] content) {
        File yourFile = new File(outputFilePath);
        try{
            if (!yourFile.exists()) {
                yourFile.createNewFile(); // if file already exists will do nothing
            }
            FileOutputStream oFile = new FileOutputStream(yourFile, true);
            oFile.write(content);
            oFile.close();
        } catch (IOException e){
            e.printStackTrace();
        }
    }


}
