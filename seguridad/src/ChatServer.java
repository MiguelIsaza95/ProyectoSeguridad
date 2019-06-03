import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ChatServer {

	private static final int PORT = 9001;

	private static HashSet<String> names = new HashSet<String>();

	private static HashSet<PrintWriter> writers = new HashSet<PrintWriter>();

	public static void main(String[] args) throws Exception {
		System.out.println("The chat server is running.");

		ServerSocket listener = new ServerSocket(PORT);
		try {
			while (true) {
				new Handler(listener.accept()).start();
			}
		} finally {
			listener.close();
		}
	}

	private static class Handler extends Thread {
		private String name;
		private Socket socket;
		private BufferedReader in;
		private PrintWriter out;

		public Handler(Socket socket) {
			this.socket = socket;
		}

		public void run() {
			try {

				in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				out = new PrintWriter(socket.getOutputStream(), true);

				while (true) {

					String intercambio = in.readLine();
					if (intercambio.startsWith("diffie")) {

						try {
							diffieservidor();
						} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
								| ClassNotFoundException e) { // TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

					out.println("SUBMITNAME");
					// recibe el nombre
					name = in.readLine();
					if (name == null) {
						return;
					}
					synchronized (names) {
						if (!names.contains(name)) {

							names.add(name);
							break;
						}
					}
				}

				//
				// envia que el nombre es aceptado y lo agrega a los escritores
				// para ver si ese nombre de
				// cliente ya existe
				out.println("NAMEACCEPTED");
				writers.add(out);

				while (true) {
					// recibe el mensaje
					String input = in.readLine();
					System.out.println("encriptado en el servidor " + input);

					if (input == null) {
						return;
					}
					for (PrintWriter writer : writers) {
						// aqui es donde envia con el nombre de quien lo mand
						writer.println("MESSAGE " + name + ": " + input);
					}
				}
			} catch (IOException e) {
				System.out.println(e);
			} finally {

				if (name != null) {
					names.remove(name);
				}
				if (out != null) {
					writers.remove(out);
				}
				try {
					socket.close();
				} catch (IOException e) {
				}
			}
		}
	}

	public static void diffieservidor() throws IOException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeyException {
		int bitLength = 1024;
		BigInteger p;
		BigInteger g;
		

		// VARIABLE PARA MANEJAR MENSAJES DEL CLIENTE
		String entry;
		// SOCKET QUE DEJA AL SERVIDOR ESPERANDO
		ServerSocket socketServidor = new ServerSocket(15210);
		System.out.println("Ya inicializo el SocketServidor");
		// ESPERA QUE SE CONECTE EL CLIENTE
		Socket client = socketServidor.accept();
		System.out.println("Ya se conecto el usuario para la descarga");

		// CANALES PARA INTERCAMBIAR INFORMACION
		ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(client.getInputStream());

		BufferedReader inFromClient = new BufferedReader(new InputStreamReader(client.getInputStream()));
		BufferedWriter OutFromServer = new BufferedWriter(new OutputStreamWriter(client.getOutputStream()));

		
	

		// GENERACION DE CLAVE COMPARTIDA POR MEDIO DEL ALGORITMO DIFFIE HELLMAN
		OutFromServer.write("GENERAR DH\n");
		OutFromServer.flush();
		entry = inFromClient.readLine();
		System.out.println("From Client: " + entry);
		// g = random(k);
		SecureRandom rnd = new SecureRandom();
		g = BigInteger.probablePrime(bitLength, rnd);
		if (entry.equals("LISTO PARA GENERAR DH")) {
			OutFromServer.write(g.toString() + "\n");
			System.out.println("Parametro G generado y enviado" + "g = " + g + "");
			OutFromServer.flush();
		}
		entry = inFromClient.readLine();
		System.out.println(entry);
		p = new BigInteger(entry);
		System.out.println("Parametro P: " + p + "");
		DHParameterSpec dhParams = new DHParameterSpec(g, p); // CREA LOS PARAMETROS PARA LA CREACION DE LA CLAVE
		System.out.println("parametros diffie Hellman generados");
		KeyPairGenerator serverKeyGen = KeyPairGenerator.getInstance("DH");// DECLARAR EL GENERADOR DE CLAVES EN MODO DH
																			// - Diffie Hellman
		serverKeyGen.initialize(dhParams, new SecureRandom()); //
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
		KeyPair serverPair = serverKeyGen.generateKeyPair();

		Key clientePublicKey = (Key) ois.readObject(); // RECIBE CLAVE PUBLICA DEL CLIENTE
		System.out.println("Recibi clave publica cliente: " + clientePublicKey.toString());
		oos.writeObject(serverPair.getPublic());
		oos.flush(); // ENVIA CLAVE PUBLICA DEL SERVIDOR
		System.out.println("Envie clave publia (servidor): " + serverPair.getPublic().toString());
		serverKeyAgree.init(serverPair.getPrivate());
		serverKeyAgree.doPhase(clientePublicKey, true);
		byte[] serverSharedSecret = serverKeyAgree.generateSecret();
		SecretKeySpec claveServer = new SecretKeySpec(serverSharedSecret, 0, 16, "AES");
		System.out.println("Clave secreta: " + claveServer.toString());

		socketServidor.close();
		System.out.println("intercambio exitoso servidor======================");

	}

}