package system.symmetric;

import common.AuthenticationClient;

import javax.crypto.SecretKey;

public class AESClient extends AuthenticationClient {

    public AESClient(String host, int port, SecretKey sharedKey) {
        super(host, port, new AESCryptoService(sharedKey));
    }

    public static void main(String[] args) {
        String host = "localhost";
        int serverPort = 5000;

        if (args.length > 0) host = args[0];
        if (args.length > 1) {
            try {
                serverPort = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Error getting server port. Using default: 5000");
            }
        }

        try {
            SecretKey sharedKey = KeyManager.getOrCreateSharedKey();
            AESClient client = new AESClient(host, serverPort, sharedKey);
            client.start();

        } catch (Exception e) {
            System.err.println("Error:");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
