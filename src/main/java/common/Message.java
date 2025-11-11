package common;

import java.io.Serial;
import java.io.Serializable;

public class Message implements Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private String username;
    private AuthStatus status;
    private String message;
    private byte[] encryptedData;
    private byte[] signature;

    public Message() {
        this.status = AuthStatus.PENDING;
    }

    public Message(String username, byte[] encryptedData) {
        this();
        this.username = username;
        this.encryptedData = encryptedData;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public AuthStatus getStatus() {
        return status;
    }

    public void setStatus(AuthStatus status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public String toString() {
        return "Message {" +
                "\n\tusername='" + username + '\'' + ',' +
                "\n\tstatus=" + status + ',' +
                "\n\tmessage='" + message + '\'' + ',' +
                "\n}";
    }
}
