import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class ClienteUDP {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static DatagramSocket socket;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        socket = new DatagramSocket();
        KeyPair claves = generarClave();
        publicKey = claves.getPublic();
        privateKey = claves.getPrivate();
        enviarClave(publicKey);

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Ingrese su nombre: ");
        String nombre = reader.readLine();
        enviarMensaje(nombre);

        Thread threadA = new Thread(() -> {
            while (true) {
                try {
                    System.out.print("Ingrese el mensaje: ");
                    String mensaje = reader.readLine();
                    enviarMensaje(nombre + ": " + mensaje);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        threadA.start();

        Thread threadB = new Thread(() -> {
            while (true) {
                byte[] recibido = new byte[1024];
                DatagramPacket paqueteRecibido = new DatagramPacket(recibido, recibido.length);
                try {
                    socket.receive(paqueteRecibido);
                    String paqueteRecibidoString = new String(recibido, 0, paqueteRecibido.getLength());
                    String desencriptado = desencriptar(paqueteRecibidoString);
                    System.out.println(desencriptado);
                } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException |
                         InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        threadB.start();
    }

    private static String desencriptar(String paqueteRecibido) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cifrado = Cipher.getInstance("RSA");
        cifrado.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] desencriptado = cifrado.doFinal(Base64.getDecoder().decode(paqueteRecibido));
        return new String(desencriptado);
    }

    private static void enviarMensaje(String mensaje) throws IOException {
        byte[] bytes = mensaje.getBytes();
        DatagramPacket paquete = new DatagramPacket(bytes, bytes.length, InetAddress.getLocalHost(), 1234);
        socket.send(paquete);
    }

    private static void enviarClave(PublicKey publicKeyEC) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutputStream oas = new ObjectOutputStream(byteOut);
        oas.writeObject(publicKeyEC);
        byte[] bytesPublica = byteOut.toByteArray();
        DatagramPacket publicData = new DatagramPacket(bytesPublica, bytesPublica.length, InetAddress.getLocalHost(), 1234);
        socket.send(publicData);
    }

    private static KeyPair generarClave() throws NoSuchAlgorithmException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        return generador.generateKeyPair();
    }
}

