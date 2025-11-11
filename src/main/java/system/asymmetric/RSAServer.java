package system.asymmetric;

import common.AuthenticationServer;

public class RSAServer extends AuthenticationServer {

    public RSAServer(int port) throws Exception {
        super(port, new RSACryptoService(true)); // true == server
    }

    public static void main(String[] args) {
        int port = 7778;

        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port. Using default: 7778");
            }
        }

        try {
            RSAServer server = new RSAServer(port);
            server.start();
        } catch (Exception e) {
            System.err.println("Error starting RSA server: ");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
