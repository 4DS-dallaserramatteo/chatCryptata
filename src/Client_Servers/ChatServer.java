package Client_Servers;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class ChatServer extends Thread {
    // Mappa per associare ciascun partecipante al proprio PrintWriter
    private static Map<String, PrintWriter> partecipanti = new HashMap<>();
    private static Map<String, SecretKey> chiaviAES = new HashMap<>();
    private static KeyPair rsaCoppiaChiave;

    static {
        try {
            KeyPairGenerator coppiaChiaveGen = KeyPairGenerator.getInstance("RSA");
            coppiaChiaveGen.initialize(2048);
            rsaCoppiaChiave = coppiaChiaveGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Socket socket;
    private PrintWriter out;
    private String username;

    public ChatServer(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            out.println("CHIAVE_PUBBLICA: " + Base64.getEncoder().encodeToString(rsaCoppiaChiave.getPublic().getEncoded()));
            String chiaveAESCryptata = in.readLine();
            if (chiaveAESCryptata.startsWith("CHIAVE_AES: ")) {
                chiaveAESCryptata = chiaveAESCryptata.substring(12);
            }
            riceviChiaveAES(chiaveAESCryptata, socket);

            out.println("Inserisci il tuo nome utente: ");
            username = in.readLine();
            while (username == null || username.trim().isEmpty() || partecipanti.containsKey(username)) {
                out.println("Nome utente non valido o già in uso. Inserisci un altro nome utente:");
                username = in.readLine();
            }

            //sostituisce il socket con lo username nell mappa delle chiavi
            synchronized (chiaviAES) {
                SecretKey aesChiave = chiaviAES.remove(socket.toString());
                chiaviAES.put(username, aesChiave);
            }

            synchronized (partecipanti) {
                partecipanti.put(username, out);
                broadcast("[Server]: " + username + " si è unito alla chat.");
            }

            String message;
            while ((message = in.readLine()) != null) {
                if (message.startsWith("READ:")) {

                    String messageId = message.substring(5);
                } else {
                    String messaggioDecryptato = decrypt(message, username);
                    // Genera un ID per il messaggio
                    String messageId = UUID.randomUUID().toString();

                    // Invia il messaggio a tutti i partecipanti
                    broadcast(username + ": " + messaggioDecryptato + " (ID: " + messageId + ")");
                    broadcast("Messaggio criptato: " + message);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            synchronized (partecipanti) {
                if (username != null) {
                    partecipanti.remove(username);
                    broadcast("[Server]: " + username + " ha lasciato la chat.");
                }
            }
        }
    }

    private void broadcast(String message) {
        synchronized (partecipanti) {
            PrintWriter writer;
            for (String usernameEsterni : partecipanti.keySet()) {
                writer = partecipanti.get(usernameEsterni);
                writer.println(encrypt(message, usernameEsterni));
            }
        }
    }

    //Usa socket per la prima connessione dove non si conosce il username
    private void riceviChiaveAES(String chiaveAESCryptata, Socket clientSocket) {
        try {
            Cipher cifrarioRSA = Cipher.getInstance("RSA");
            cifrarioRSA.init(Cipher.DECRYPT_MODE, rsaCoppiaChiave.getPrivate());
            byte[] chiaveDecryptata = cifrarioRSA.doFinal(Base64.getDecoder().decode(chiaveAESCryptata));
            SecretKey aesChiave = new SecretKeySpec(chiaveDecryptata, "AES");
            synchronized (chiaviAES) {
                chiaviAES.put(clientSocket.toString(), aesChiave);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String decrypt(String messaggioCryptato, String username) {
        try {
            SecretKey chiaveAES = chiaviAES.get(username);

            Cipher cifrarioAES = Cipher.getInstance("AES");
            cifrarioAES.init(Cipher.DECRYPT_MODE, chiaveAES);
            byte[] decryptato = cifrarioAES.doFinal(Base64.getDecoder().decode(messaggioCryptato));
            return new String(decryptato);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String encrypt(String messaggio, String username) {
        try {
            SecretKey chiaveAES = chiaviAES.get(username);

            Cipher cifrarioAES = Cipher.getInstance("AES");
            cifrarioAES.init(Cipher.ENCRYPT_MODE, chiaveAES);
            byte[] cryptato = cifrarioAES.doFinal(messaggio.getBytes());
            return Base64.getEncoder().encodeToString(cryptato);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
