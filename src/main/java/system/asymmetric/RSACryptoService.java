package system.asymmetric;

import common.Environment;
import performance.PerformanceLogger;
import system.CryptoService;

import javax.crypto.Cipher;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ConcurrentHashMap;

public class RSACryptoService implements CryptoService {
    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;

    private final KeyPair keyPair;
    private final boolean isServer;
    private final ConcurrentHashMap<Socket, PublicKey> publicKeyMap = new ConcurrentHashMap<>();
    private PerformanceLogger logger;

    public RSACryptoService(boolean isServer) throws Exception {
        this.isServer = isServer;

        String role = isServer ? "Server" : "Client";
        System.out.println("[" + role + "] Generating RSA key pair...");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE);
        this.keyPair = keyGen.generateKeyPair();

        System.out.println("[" + role + "] RSA key pair generated (2048-bit)");
        warmUp();

        try {
            String systemName = "RSA";
            this.logger = new PerformanceLogger(systemName);
        } catch (Exception e) {
            System.err.println("Logger error: " + e.getMessage());
        }
    }

    private void warmUp() {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(keyPair.getPrivate());
        } catch (Exception e) {}
    }

    @Override
    public byte[] encrypt(byte[] data, Socket targetSocket) throws Exception {
        PerformanceLogger.Timer timer = new PerformanceLogger.Timer();
        timer.start();

        PublicKey targetPublicKey = publicKeyMap.get(targetSocket);
        if (targetPublicKey == null) {
            System.err.println("!!! Public key not found for socket: " + targetSocket);
            System.err.println("Available sockets in map: " + publicKeyMap.keySet());
            throw new IllegalStateException("Public key not found for socket: "
                    + targetSocket.getRemoteSocketAddress());
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, targetPublicKey);
        byte[] result = cipher.doFinal(data);

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

        Cipher decipher = Cipher.getInstance(ALGORITHM);
        decipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] result = decipher.doFinal(encryptedData);

        double duration = timer.stopMs();
        if (logger != null) {
            logger.log("decrypt", duration);
        }

        return result;
    }

    @Override
    public boolean requiresHandshake() {
        return true;
    }

    @Override
    public void performHandshake(Socket targetSocket) throws Exception {
        if (isServer) {
            System.out.println("[HANDSHAKE] Waiting for client public key...");
            PublicKey clientPublicKey = receivePublicKey(targetSocket);
            publicKeyMap.put(targetSocket, clientPublicKey);
            System.out.println("Received client public key (RSA-2048) for: "
                    + targetSocket.getRemoteSocketAddress());

            System.out.println("[HANDSHAKE] Sending server public key...");
            sendPublicKey(targetSocket, keyPair.getPublic());
            System.out.println("Sent server public key to client!");
        } else {
            System.out.println("[HANDSHAKE] Sending client public key...");
            sendPublicKey(targetSocket, keyPair.getPublic());
            System.out.println("Sent client public key to server!");

            System.out.println("[HANDSHAKE] Waiting for server public key...");
            PublicKey serverPublicKey = receivePublicKey(targetSocket);
            publicKeyMap.put(targetSocket, serverPublicKey);
            System.out.println("Received server public key (RSA-2048)");
        }
    }

    private void sendPublicKey(Socket socket, PublicKey publicKey) throws Exception {
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.writeObject(publicKey.getEncoded());
        out.flush();
    }

    private PublicKey receivePublicKey(Socket socket) throws Exception {
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        byte[] publicKeyBytes = (byte[]) in.readObject();

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    public byte[] sign(byte[] data) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    public boolean verify(byte[] data, byte[] signatureBytes, Socket senderSocket) throws Exception {
        PublicKey senderPublicKey = publicKeyMap.get(senderSocket);
        if (senderPublicKey == null) {
            System.err.println("!!! Public key not found for socket: " + senderSocket);
            System.err.println("Available sockets in map: " + publicKeyMap.keySet());
            throw new IllegalStateException("Public key not found for socket: "
                    + senderSocket.getRemoteSocketAddress());
        }
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(senderPublicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    @Override
    public String getAlgorithmName() {
        return "RSA-2048";
    }

    @Override
    public Environment getEnvironment() {
        return Environment.ASYMMETRIC;
    }
}
