package Client_Servers;

import java.io.IOException;
import java.net.ServerSocket;


public class MultiServer {

    private static final int PORT = 777;

    public static void main(String args[]) {
        MultiServer s = new MultiServer();
        s.attendi();
    }

    public void attendi() {
        try {
            while (true) {
                System.out.println("Chat server started...");
                try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                    while (true) {
                        new ChatServer(serverSocket.accept()).start();
                    }
                } catch (IOException e) {
                    System.out.println("Error starting server: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}