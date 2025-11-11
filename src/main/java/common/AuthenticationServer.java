package common;

import system.CryptoService;
import system.asymmetric.RSACryptoService;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class AuthenticationServer {
    protected int port;
    protected CryptoService cryptoService;
    protected Map<String, String> userDatabase;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private ServerSocket serverSocket;

    public AuthenticationServer(int port, CryptoService cryptoService) {
        this.port = port;
        this.cryptoService = cryptoService;
        this.userDatabase = new HashMap<>();
        initializeUsers();
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);

        registerShutdownHook();

        System.out.println("=========================================================");
        System.out.println("Server started on port: " + port);
        System.out.println("Algorithm: " + cryptoService.getAlgorithmName());
        System.out.println("Environment: " + cryptoService.getEnvironment());
        System.out.println("Awaiting clients...");
        System.out.println("===================================");

        while (running.get()) {
            try {
                Socket clientSocket = serverSocket.accept();

                if (!running.get()) {
                    clientSocket.close();
                    break;
                }

                System.out.println("New client connected!");
                System.out.println("\t> Port: " + clientSocket.getPort());
                System.out.println("===================================");

                new Thread(() -> handleClient(clientSocket)).start();

            } catch (SocketException e) {
                if (!running.get()) {
                    break;
                }
                throw e;
            }
        }
    }

    protected void handleClient(Socket socket) {
        try {
            if (cryptoService.requiresHandshake()) {
                System.out.println("[HANDSHAKE] Starting handshake...");
                cryptoService.performHandshake(socket);
                System.out.println("[HANDSHAKE] Handshake completed!");
            }

            System.out.println("[AUTH] Waiting for login request...");
            Message loginRequest = receiveMessage(socket);
            if (loginRequest == null) return;

            byte[] decryptedData = cryptoService.decrypt(loginRequest.getEncryptedData());
            String credentials = new String(decryptedData, StandardCharsets.UTF_8);

            CryptoUtils.logEncryptedMessage(loginRequest.getEncryptedData(), decryptedData);

            String[] parts = credentials.split(":");

            if (parts.length != 2) {
                sendErrorResponse(socket, "Invalid credential format.");
                return;
            }

            String username = parts[0];
            String password = parts[1];

            System.out.println("[AUTH] Client is attempting login: " + username);

            boolean authenticated = authenticate(username, password);

            Message response = new Message();
            if (authenticated) {
                response.setStatus(AuthStatus.SUCCESS);
                response.setMessage("Welcome, " + username + "! Authentication successful!");
                System.out.println("[AUTH] Authentication SUCCESSFUL for: " + username);
            } else {
                response.setStatus(AuthStatus.FAILED);
                response.setMessage("Invalid username or password.");
                System.out.println("[AUTH] Authentication FAILED for: " + username);
            }

            sendMessage(socket, response);

            if (authenticated) {
                handleSecureCommunication(socket, username);
            }

            System.out.println("=======================================");

        } catch (EOFException e) {
            System.out.println("[COMMUNICATION] Client closed the connection without sending a message.");
        } catch (Exception e) {
            System.err.println("Error authenticating client: " + e.getMessage());
            e.printStackTrace();
        } finally {
            closeClientSocket(socket);
        }
    }

    protected void handleSecureCommunication(Socket targetSocket, String username) throws Exception {
        System.out.println("[COMMUNICATION] Waiting for additional message of: " + username);

        Message clientMessage = receiveMessage(targetSocket);
        byte[] decrypted = cryptoService.decrypt(clientMessage.getEncryptedData());
        String messageText = new String(decrypted, StandardCharsets.UTF_8);

        CryptoUtils.logEncryptedMessage(clientMessage.getEncryptedData(), decrypted);

        System.out.println("[COMMUNICATION] " + username + " says: " + messageText);

        Message response = new Message();
        response.setStatus(AuthStatus.SUCCESS);
        response.setMessage("Server: I have received your message, you said: '" + messageText + "'");

        sendMessage(targetSocket, response);
        System.out.println("[COMMUNICATION] Response was sent to the client.");
    }

    protected boolean authenticate(String username, String password) {
        if (!userDatabase.containsKey(username)) {
            return false;
        }

        String storedHash = userDatabase.get(username);
        String providedHash = hashPassword(password);
        return storedHash.equals(providedHash);
    }

    protected void sendErrorResponse(Socket targetSocket, String errorMessage) throws Exception {
        Message response = new Message();
        response.setStatus(AuthStatus.FAILED);
        response.setMessage(errorMessage);
        sendMessage(targetSocket, response);
    }

    protected Message receiveMessage(Socket socket) throws Exception {
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        return (Message) in.readObject();
    }

    protected void sendMessage(Socket targetSocket, Message msg) throws Exception {
        byte[] encrypted = cryptoService.encrypt(
                msg.getMessage().getBytes(StandardCharsets.UTF_8),
                targetSocket
        );
        msg.setEncryptedData(encrypted);
        if (cryptoService.getEnvironment() == Environment.ASYMMETRIC) {
            if (cryptoService instanceof RSACryptoService rsaCrypto) {
                byte[] signature = rsaCrypto.sign(msg.getMessage().getBytes(StandardCharsets.UTF_8));
                msg.setSignature(signature);

                System.out.println("Message has been signed with digital signature.");
            }
        }
        ObjectOutputStream out = new ObjectOutputStream(targetSocket.getOutputStream());
        out.writeObject(msg);
        out.flush();
    }

    protected String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error while hashing password.", e);
        }
    }

    protected void initializeUsers() {
        userDatabase.put("alice", hashPassword("password123"));
        userDatabase.put("bob", hashPassword("secret456"));
        userDatabase.put("admin", hashPassword("admin"));
        System.out.println("\nInitialized test users:");
        System.out.println("> alice / password123");
        System.out.println("> bob / secret456");
        System.out.println("> admin / admin");
    }

    private void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n\n!!! Stopping server...");
            shutdown();
        }));
    }

    public void shutdown() {
        if (running.compareAndSet(true, false)) {
            System.out.println("Closing server socket...");
            closeServerSocket();
        }
    }

    private void closeServerSocket() {
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
                System.out.println("Server socket closed!");
            } catch (IOException e) {
                System.err.println("Error while closing server socket" + e.getMessage());
            }
        }
    }

    private void closeClientSocket(Socket socket) {
        if (socket != null && !socket.isClosed()) {
            try {
                socket.close();
                System.out.println("Client socket closed! " + socket.getRemoteSocketAddress());
                System.out.println("=======================================\n");
            } catch (IOException e) {}
        }
    }
}
