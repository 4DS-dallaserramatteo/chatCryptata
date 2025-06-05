package Client_Servers;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 777;

    private SecretKey chiaveAES;

    public static void main(String[] args) {
        Client c = new Client();
        c.comunica();
    }

    public void comunica() {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT); PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            Scanner scanner = new Scanner(System.in);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    socket.close();
                    System.out.println("Connessione chiusa");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }));

            creaChiaveAES();

            String chiavePubblicaServer = in.readLine();
            System.out.println(chiavePubblicaServer);
            if (chiavePubblicaServer.startsWith("CHIAVE_PUBBLICA: ")) {
                chiavePubblicaServer = chiavePubblicaServer.substring(17);
                String chiaveAESCryptata = cryptaChiaveAES(chiavePubblicaServer);
                out.println("CHIAVE_AES: " + chiaveAESCryptata);
            }


            if (in.readLine().startsWith("Inserisci il tuo nome utente: ")) {
                System.out.println("Inserisci il tuo nome utente: ");
                String username = scanner.nextLine();
                out.println(username);
            }

            CompletableFuture.runAsync(() -> {
                try {
                    String message;
                    while ((message = in.readLine()) != null) {
                        message = decrypta(message);
                        System.out.println("\n" + message);


                        if (message.contains("ID: ")) {
                            String messageId = message.substring(message.indexOf("ID: ") + 4, message.indexOf(")"));
                            out.println("READ:" + messageId);
                        }
                    }
                } catch (IOException e) {
                    System.out.println("Errore nel ricevere messaggi: " + e.getMessage());
                }
            });

            // Interazione utente
            System.out.println("Connesso al server di chat");
            while (true) {
                String message = scanner.nextLine();
                out.println(encrypt(message));
            }


        } catch (IOException e) {
            System.out.println("Errore di connessione al server: " + e.getMessage());
        }
    }

    private void creaChiaveAES() {
        try {
            KeyGenerator genChiave = KeyGenerator.getInstance("AES");
            genChiave.init(256);
            chiaveAES = genChiave.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String cryptaChiaveAES(String chiavePubblicaString) {
        try {
            byte[] chiavePubblicaByte = Base64.getDecoder().decode(chiavePubblicaString);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey chiavePubblica = keyFactory.generatePublic(new X509EncodedKeySpec(chiavePubblicaByte));

            Cipher cifrarioRSA = Cipher.getInstance("RSA");
            cifrarioRSA.init(Cipher.ENCRYPT_MODE, chiavePubblica);
            byte[] chiaveCryptata = cifrarioRSA.doFinal(chiaveAES.getEncoded());
            return Base64.getEncoder().encodeToString(chiaveCryptata);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String encrypt(String messaggio) {
        try {
            messaggio = messaggio.trim();
            Cipher cifrarioAES = Cipher.getInstance("AES");
            cifrarioAES.init(Cipher.ENCRYPT_MODE, chiaveAES);
            byte[] criptato = cifrarioAES.doFinal(messaggio.getBytes());
            return Base64.getEncoder().encodeToString(criptato);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String decrypta(String messaggioCriptato) {
        try {
            Cipher cifrarioAES = Cipher.getInstance("AES");
            cifrarioAES.init(Cipher.DECRYPT_MODE, chiaveAES);
            byte[] decriptato = cifrarioAES.doFinal(Base64.getDecoder().decode(messaggioCriptato));
            return new String(decriptato);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
