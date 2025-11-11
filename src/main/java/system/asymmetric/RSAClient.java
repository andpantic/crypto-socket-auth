package system.asymmetric;

import common.AuthenticationClient;

public class RSAClient extends AuthenticationClient {

    public RSAClient(String host, int port) throws Exception {
        super(host, port, new RSACryptoService(false)); // false == client
    }

    public static void main(String[] args) {
        String host = "localhost";
        int port = 7778;

        if (args.length > 0) host = args[0];
        if (args.length > 1) {
            try {
                port = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid server port. Using default: 7778");
            }
        }

        try {
            RSAClient client = new RSAClient(host, port);
            client.start();
        } catch (Exception e) {
            System.err.println("Error:");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
