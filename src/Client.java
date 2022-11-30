import javax.crypto.Cipher;
import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Client {
    private static final String USERNAME = "RONALDO";
    private static final String SERIAL = "1234-5678-9123";
    private static String MAC;
    private static String DISK_SERIAL;
    private static String MOTHERBOARD_SERIAL;
    private PublicKey publicKey;

    // TODO: Raporda randomnesstan bahsederken şu linke bak : https://stackoverflow.com/questions/16325057/why-does-rsa-encrypted-text-give-me-different-results-for-the-same-text

    public Client() throws Exception {
        try {
            this.getHardwareSpecificInfo();
        } catch (Exception e) {
            e.printStackTrace();
        }
        starterLogs();
        byte[] publicKeyFile = Client.readFileAsByteArray("public.key");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyFile));
    }

    public static void main(String[] args) throws Exception {
        Client client = new Client();

        String userSpecificInfo = client.getUserSpecificInfo();
        byte[] encryptedInfo = client.encrypt(userSpecificInfo);

        client.licenseProcess(encryptedInfo);
    }

    private void getHardwareSpecificInfo() throws Exception {
        this.MAC = Client.getMacAddress();
        this.DISK_SERIAL = Client.getDiskSerialNumber();
        this.MOTHERBOARD_SERIAL = Client.getMotherboardSerial();
    }

    public static String getMacAddress() throws Exception {
        InetAddress localHost = InetAddress.getLocalHost();
        NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
        byte[] hardwareAddress = ni.getHardwareAddress();

        String[] hexadecimal = new String[hardwareAddress.length];
        for (int i = 0; i < hardwareAddress.length; i++) {
            hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
        }
        return String.join(":", hexadecimal);
    }

    public static String getDiskSerialNumber() throws Exception{
        Runtime runtime = Runtime.getRuntime();
        String[] commands = {"wmic", "diskdrive", "get", "serialnumber"};
        Process process = runtime.exec(commands);
        String chain = null;
        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String serialNumber = null;
            while ((serialNumber = bufferedReader.readLine()) != null) {
                if (serialNumber.trim().length() > 0) {
                    chain = serialNumber;
                }
            }
            return chain.trim();
        }
    }

    public static String getMotherboardSerial() {
        // command to be executed on the terminal
        String command = "wmic baseboard get serialnumber";

        // variable to store the Serial Number
        String serialNumber = null;

        try {

            // declaring the process to run the command
            Process SerialNumberProcess = Runtime.getRuntime().exec("wmic baseboard get serialnumber");

            // getting the input stream using
            // InputStreamReader using Serial Number Process
            InputStreamReader ISR = new InputStreamReader(SerialNumberProcess.getInputStream());

            // declaring the Buffered Reader
            BufferedReader br = new BufferedReader(ISR);

            // reading the serial number using
            // Buffered Reader
            br.readLine();
            br.readLine();
            serialNumber = br.readLine().trim();

            // waiting for the system to return
            // the serial number
            SerialNumberProcess.waitFor();

            // closing the Buffered Reader
            br.close();
        }

        // catch block
        catch (Exception e) {

            // printing the exception
            e.printStackTrace();

            // giving the serial number the value null
            serialNumber = null;
        }
        return serialNumber;
        // try block

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

    private void licenseProcess(byte[] encryptedInfo) throws Exception {
        if (this.isLicenseFileExists()) {
            byte[] license = Client.readFileAsByteArray("license.txt");
            System.out.println("Client - License is found.");

            try {
                if (this.verifySignature(license)) {
                    System.out.println("Client - Succeed. The license is correct.");
                } else {
                    System.out.println("Client - The license file has been broken!!");
                    this.createLicense(encryptedInfo);
                }
            } catch (Exception e) {
                System.out.println("Client - The license file has been broken!!");
                this.createLicense(encryptedInfo);
            }
        } else {
            System.out.println("Client - License file is not found!");
            this.createLicense(encryptedInfo);
        }
    }

    private void createLicense(byte[] encryptedInfo) throws Exception {
        LicenseManager licenseManager = new LicenseManager(encryptedInfo);

        System.out.println("Client - Raw License Text: " + this.getUserSpecificInfo());
        // TODO: Yiyo
        System.out.println("Client - Encrypted License Text: " + Base64.getEncoder().encodeToString(encryptedInfo));
        System.out.println("Client - MD5 License Text: " + Client.byteArrayToHexString(
                this.hash(this.getUserSpecificInfo().getBytes(StandardCharsets.UTF_8))));
        byte[] signature = licenseManager.getSignature();

        if (this.verifySignature(signature)) {
            System.out.println("Client - Succeed. The license file content is secured and signed by the server.");
        } else {
            System.out.println("Client - Failed. The license file content can not be verified.");
        }
        Client.writeFile("license.txt", signature);
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
            FileOutputStream oFile = new FileOutputStream(yourFile);
            oFile.write(content);
            oFile.close();
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    public static String byteArrayToHexString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        final StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
