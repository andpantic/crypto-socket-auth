package system.symmetric;

import common.Environment;
import performance.PerformanceLogger;
import system.CryptoService;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.net.Socket;
import java.security.SecureRandom;

public class AESCryptoService implements CryptoService {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final SecretKey secretKey;
    private final SecureRandom random;
    private PerformanceLogger logger;

    public AESCryptoService(SecretKey sharedKey) {
        this.secretKey = sharedKey;
        this.random = new SecureRandom();
        warmUp();
        try {
            this.logger = new PerformanceLogger("AES");
        } catch (Exception e) {
            System.err.println("Logger error: " + e.getMessage());
        }
    }

    @Override
    public byte[] encrypt(byte[] data, Socket targetSocket) throws Exception {
        PerformanceLogger.Timer timer = new PerformanceLogger.Timer();
        timer.start();
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] cipherText = cipher.doFinal(data);
        byte[] result = concat(iv, cipherText);

        double duration = timer.stopMs();
        if (logger != null) {
            logger.log("encrypt", duration);
        }

        return result;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        PerformanceLogger.Timer timer = new PerformanceLogger.Timer();
        timer.start();
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);

        int ciphertextLength = encryptedData.length - GCM_IV_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(encryptedData, GCM_IV_LENGTH, ciphertext, 0, ciphertextLength);

        Cipher decipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        decipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] result = decipher.doFinal(ciphertext);

        double duration = timer.stopMs();
        if (logger != null) {
            logger.log("decrypt", duration);
        }

        return result;
    }

    private void warmUp() {
        try {
            byte[] dummy = new byte[GCM_IV_LENGTH];
            random.nextBytes(dummy);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, dummy);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            cipher.doFinal(new byte[16]);
        } catch (Exception e) {}
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    @Override
    public boolean requiresHandshake() {
        return false;
    }

    @Override
    public void performHandshake(Socket socket) {}

    @Override
    public String getAlgorithmName() {
        return "AES-256-GCM";
    }

    @Override
    public Environment getEnvironment() {
        return Environment.SYMMETRIC;
    }
}
