package common;

import java.nio.charset.StandardCharsets;

public class CryptoUtils {

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void logEncryptedMessage(byte[] encryptedData, byte[] decryptedData) {
        System.out.println("=> Encrypted received message (" + encryptedData.length + " bytes): " +
                bytesToHex(encryptedData));
        System.out.println("=> Decrypted received message: " + new String(decryptedData, StandardCharsets.UTF_8));
    }
}
