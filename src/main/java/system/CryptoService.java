package system;

import common.Environment;

import java.net.Socket;

public interface CryptoService {
    byte[] encrypt(byte[] data, Socket targetSocket) throws Exception;
    byte[] decrypt(byte[] encryptedData) throws Exception;
    boolean requiresHandshake();
    void performHandshake(Socket socket) throws Exception;
    String getAlgorithmName();
    Environment getEnvironment();
}
