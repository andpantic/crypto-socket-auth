package system.symmetric;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

public class KeyManager {
    private static final String KEY_FILE = "src/main/resources/aes_shared.key";
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    public static SecretKey getOrCreateSharedKey() throws Exception {
        Path keyPath = Paths.get(KEY_FILE);

        if (Files.exists(keyPath)) {
            return loadKeyFromFile(keyPath);
        } else {
            return generateAndSaveKey(keyPath);
        }
    }

    private static SecretKey loadKeyFromFile(Path keyPath) throws IOException {
        System.out.println("\n=========================================================");
        System.out.println("Loading key from file: " + KEY_FILE);
        byte[] keyBytes = Files.readAllBytes(keyPath);

        if (keyBytes.length != KEY_SIZE / 8) {
            throw new IOException("Invalid key format, expected: " +
                    (KEY_SIZE / 8) + " bytes, found: " + keyBytes.length);
        }

        System.out.println("Key successfully loaded (" + keyBytes.length + " bytes)");
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    private static SecretKey generateAndSaveKey(Path keyPath)
            throws NoSuchAlgorithmException, IOException {
        System.out.println("!!! GENERATING NEW AES KEY... !!!");

        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        SecretKey key = keyGen.generateKey();

        Files.write(keyPath, key.getEncoded());
        System.out.println("Key successfully generated and saved to: " + KEY_FILE);
        return key;
    }
}
