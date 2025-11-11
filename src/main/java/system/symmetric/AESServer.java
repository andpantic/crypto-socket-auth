package system.symmetric;

import common.AuthenticationServer;

import javax.crypto.SecretKey;

public class AESServer extends AuthenticationServer {

    public AESServer(int port, SecretKey sharedKey) {
        super(port, new AESCryptoService(sharedKey));
    }

    public static void main(String[] args) {
        int port = 5000;

        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Error getting port. Using default: 5000");
            }
        }

        try {
            SecretKey sharedKey = KeyManager.getOrCreateSharedKey();
            AESServer server = new AESServer(port, sharedKey);
            server.start();

        } catch (Exception e) {
            System.err.println("\t Error starting AESServer:");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
