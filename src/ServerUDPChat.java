import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class ServerUDPChat {
    public static Map<String, SocketAddress> clientes;
    private static Map<SocketAddress, PublicKey> claves;
    private static DatagramSocket datagramSocket;
    private static ReentrantLock lock;

    public static void main(String[] args) throws IOException {
        claves = new HashMap<>();
        lock = new ReentrantLock();
        clientes = new HashMap<>();

        datagramSocket = new DatagramSocket(1234);

        Thread mensajes = new Thread(() -> {
            while (true) {
                byte[] mensaje = new byte[1024];
                DatagramPacket paquete = new DatagramPacket(mensaje, mensaje.length);
                try {
                    datagramSocket.receive(paquete);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                lock.lock();
                String paqueteString = new String(paquete.getData(), 0, paquete.getLength());
                if (paqueteString.equals("salir")) {
                    desconectar(paquete.getSocketAddress());
                } else {
                    SocketAddress direccionCliente = paquete.getSocketAddress();
                    if (clienteExiste(direccionCliente)) {
                        clientes.forEach((cliente, socket) -> {
                            String encriptado = encriptar(paqueteString, socket);
                            try {
                                if (!direccionCliente.equals(socket)) {
                                    reenviarAClientes(encriptado, socket);
                                }
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
                    } else {
                        ByteArrayInputStream inputStream = new ByteArrayInputStream(paquete.getData());
                        ObjectInputStream objectInputStream = null;
                        try {
                            objectInputStream = new ObjectInputStream(inputStream);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                        PublicKey publicKey = null;
                        try {
                            publicKey = (PublicKey) objectInputStream.readObject();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        } catch (ClassNotFoundException e) {
                            throw new RuntimeException(e);
                        }
                        claves.put(direccionCliente, publicKey);
                        clientes.put(direccionCliente.toString(), direccionCliente);
                    }
                    System.out.println("Mensaje recibio de: " + direccionCliente);
                    lock.unlock();
                }
            }
        });
        mensajes.start();
    }

    private static String encriptar(String paqueteString, SocketAddress socket) {
        byte[] encriptado;
        PublicKey publicKey = claves.get(socket);
        try {
            Cipher cifrado = Cipher.getInstance("RSA");
            cifrado.init(Cipher.ENCRYPT_MODE, publicKey);
            encriptado = cifrado.doFinal(paqueteString.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encodeToString(encriptado);
    }

    private static boolean clienteExiste(SocketAddress direccionCliente) {
        return clientes.containsValue(direccionCliente);
    }

    private static void reenviarAClientes(String paqueteString, SocketAddress socket) throws IOException {
        byte[] mensajeBytes = paqueteString.getBytes();
        DatagramPacket paquete = new DatagramPacket(mensajeBytes, mensajeBytes.length, socket);
        datagramSocket.send(paquete);
    }

    public static void desconectar(SocketAddress socketAddress) {
        String mensaje = "Cliente desconectado.";
        clientes.remove(socketAddress.toString());
        clientes.forEach((key, value) -> {
            String encriptado = encriptar(mensaje, value);
            try {
                reenviarAClientes(encriptado, value);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
