package common;

import performance.PerformanceLogger;
import system.CryptoService;
import system.asymmetric.RSACryptoService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public abstract class AuthenticationClient {
    protected String serverHost;
    protected int serverPort;
    protected CryptoService cryptoService;
    protected Scanner scanner;

    public AuthenticationClient(String host, int port, CryptoService cryptoService) {
        this.serverHost = host;
        this.serverPort = port;
        this.cryptoService = cryptoService;
        this.scanner = new Scanner(System.in);
    }

    public void start() {
        Socket socket = null;
        try {
            socket = new Socket(serverHost, serverPort);

            System.out.println("======================================");
            System.out.println("Connected to server: " + serverHost + ":" + serverPort);
            System.out.println("Algorithm: " + cryptoService.getAlgorithmName());
            System.out.println("Environment: " + cryptoService.getEnvironment());
            System.out.println("======================================");

            if (cryptoService.requiresHandshake()) {
                System.out.println("[HANDSHAKE] Starting handshake...");
                cryptoService.performHandshake(socket);
                System.out.println("[HANDSHAKE] Handshake completed!");
            }

            performLogin(socket);

        } catch (SocketException e) {
            System.err.println("\nConnection stopped: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("\nError: " + e.getMessage());
            e.printStackTrace();
        } finally {
            closeSocket(socket);
        }
    }

    protected void performLogin(Socket serverSocket) throws Exception {
        System.out.println("\t\t\t\tLOGIN");
        System.out.println("======================================");

        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Password: ");
        String password = scanner.nextLine().trim();

        PerformanceLogger.Timer authTimer = new PerformanceLogger.Timer();
        authTimer.start();

        String credentials = username + ":" + password;
        byte[] encryptedCredentials = cryptoService.encrypt(
                credentials.getBytes(StandardCharsets.UTF_8),
                serverSocket
        );

        Message loginRequest = new Message(username, encryptedCredentials);

        System.out.println("\n[AUTH] Sending encrypted credentials.");
        sendMessage(serverSocket, loginRequest);

        System.out.println("[AUTH] Awaiting server response...");
        Message response = receiveMessage(serverSocket);

        byte[] decryptedResponse = cryptoService.decrypt(response.getEncryptedData());

        if (cryptoService.getEnvironment() == Environment.ASYMMETRIC) {
            if (cryptoService instanceof RSACryptoService rsaCrypto) {
                if (response.getSignature() != null) {
                    boolean valid = rsaCrypto.verify(decryptedResponse, response.getSignature(), serverSocket);
                    if (valid) {
                        System.out.println("Server digital signature is valid!");
                    } else {
                        System.err.println("Server digital signature is INVALID");
                        return;
                    }
                }
            }
        }

        double totalAuthTime = authTimer.stopMs();
        CryptoUtils.logEncryptedMessage(response.getEncryptedData(), decryptedResponse);
        String responseText = new String(decryptedResponse, StandardCharsets.UTF_8);
        logAuthTime(totalAuthTime);

        System.out.println("\n===================================================");
        if (response.getStatus() == AuthStatus.SUCCESS) {
            System.out.println("\t\tAuthentication SUCCESSFUL!");
            System.out.println("===================================================");
            System.out.println("[AUTH] Server: " + responseText);
            performSecureCommunication(serverSocket);
        } else {
            System.out.println("\t\tAuthentication FAILED...");
            System.out.println("===================================================");
            System.out.println("[AUTH] Server: " + responseText);
        }
    }

    protected void performSecureCommunication(Socket targetSocket) throws Exception {
        System.out.println("\nSecure communication is active!");
        System.out.print("Send a message to the server (or Enter to close the connection): ");
        String userMessage = scanner.nextLine().trim();

        if (userMessage.isEmpty()) {
            System.out.println("Closing connection...");
            return;
        }

        byte[] encrypted = cryptoService.encrypt(
                userMessage.getBytes(StandardCharsets.UTF_8),
                targetSocket
        );
        Message msg = new Message();
        msg.setEncryptedData(encrypted);

        System.out.println("[COMMUNICATION] Sending encrypted message...");
        sendMessage(targetSocket, msg);

        Message serverResponse = receiveMessage(targetSocket);
        byte[] decrypted = cryptoService.decrypt(serverResponse.getEncryptedData());

        if (cryptoService.getEnvironment() == Environment.ASYMMETRIC) {
            if (cryptoService instanceof RSACryptoService rsaCrypto) {
                if (serverResponse.getSignature() != null) {
                    boolean valid = rsaCrypto.verify(decrypted, serverResponse.getSignature(), targetSocket);
                    if (!valid) {
                        System.err.println("Signature is INVALID!");
                        return;
                    }
                    System.out.println("Signature is valid");
                }
            }
        }
        CryptoUtils.logEncryptedMessage(serverResponse.getEncryptedData(), decrypted);
        String responseText = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("[COMMUNICATION] " + responseText);
    }

    private void closeSocket(Socket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
                System.out.println("\nDisconnected from server.");
            }
        } catch (IOException e) {}
        if (scanner != null) {
            scanner.close();
        }
    }

    protected void sendMessage(Socket targetSocket, Message msg) throws Exception {
        ObjectOutputStream out = new ObjectOutputStream(targetSocket.getOutputStream());
        out.writeObject(msg);
        out.flush();
    }

    protected Message receiveMessage(Socket socket) throws Exception {
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        return (Message) in.readObject();
    }

    private void logAuthTime(double durationMs) {
        try {
            String systemName = cryptoService.getEnvironment() == Environment.SYMMETRIC ?
                    "AES" : "RSA";
            PerformanceLogger logger = new PerformanceLogger(systemName);
            logger.log("auth_total", durationMs);
            logger.close();
        } catch (Exception e) {}
    }
}
