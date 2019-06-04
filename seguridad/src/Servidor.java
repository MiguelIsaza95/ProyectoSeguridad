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

/**
 * Clase encargada de establecer una comunicación entre clientes para el intercambio de mensajes.
 * @author Miguel Isaza, Steven Montealegre, Cristian Morales
 *
 */
public class Servidor {

	// Puerto por el cual el servidor espera la conexión del cliente
	private static final int PORT = 9001;

	// Hash donde se registran los nombres de los usuarios.
	private static HashSet<String> names = new HashSet<String>();

	// Hash donde se registra el mensaje a enviar
	private static HashSet<PrintWriter> writers = new HashSet<PrintWriter>();

	/**
	 * Aquí el servidor espera a la conección de los clientes que quieren comunicarse
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		ServerSocket listener = new ServerSocket(PORT);
		try {
			while (true) {
				new Handler(listener.accept()).start();
			}
		} finally {
			listener.close();
		}
	}

	/**
	 * Clase encargada de intercambiar claves con los clientes y encargada de establecer una comunicación entre
	 * estos
	 * @author Miguel Isaza, Steven Montealegre, Cristian Morales
	 *
	 */
	private static class Handler extends Thread {
		
		//Variables de la clase
		private String name;
		private Socket socket;
		private BufferedReader in;
		private PrintWriter out;

		// Se recibe la conexión del cliente
		public Handler(Socket socket) {
			this.socket = socket;
		}

		/**
		 * Se ejecuta el socket
		 */
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
								| ClassNotFoundException e) {
							e.printStackTrace();
						}
					}

					out.println("SUBMITNAME");
					
					// Recibe el nombre del usuario
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

				// Envia que el nombre es aceptado y lo agrega a los escritores para ver si ese nombre de
				// cliente ya existe
				out.println("NAMEACCEPTED");
				writers.add(out);

				while (true) {
					// Recibe el mensaje
					String input = in.readLine();

					if (input == null) {
						return;
					}
					for (PrintWriter writer : writers) {
						
						// Aquí es donde se envía el nombre de quien envía el mensaje y el mensaje
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

	/**
	 * Método encargado de generar la clave pública del servidor para intercambiarla con el cliente
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 */
	public static void diffieservidor() throws IOException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeyException {
		int bitLength = 1024;
		BigInteger p;
		BigInteger g;
		

		// VARIABLE PARA MANEJAR MENSAJES DEL CLIENTE
		String entry;
		
		// SOCKET QUE DEJA AL SERVIDOR ESPERANDO
		ServerSocket socketServidor = new ServerSocket(15210);
		
		// ESPERA QUE SE CONECTE EL CLIENTE
		Socket client = socketServidor.accept();

		// CANALES PARA INTERCAMBIAR INFORMACION
		ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(client.getInputStream());

		BufferedReader inFromClient = new BufferedReader(new InputStreamReader(client.getInputStream()));
		BufferedWriter OutFromServer = new BufferedWriter(new OutputStreamWriter(client.getOutputStream()));

		// GENERACION DE CLAVE COMPARTIDA POR MEDIO DEL ALGORITMO DIFFIE HELLMAN
		OutFromServer.write("GENERAR DH\n");
		OutFromServer.flush();
		entry = inFromClient.readLine();
		
		// g = random(k);
		SecureRandom rnd = new SecureRandom();
		g = BigInteger.probablePrime(bitLength, rnd);
		if (entry.equals("LISTO PARA GENERAR DH")) {
			OutFromServer.write(g.toString() + "\n");
			OutFromServer.flush();
		}
		entry = inFromClient.readLine();
		p = new BigInteger(entry);
		
		// CREA LOS PARAMETROS PARA LA CREACION DE LA CLAVE
		DHParameterSpec dhParams = new DHParameterSpec(g, p);
		
		// DECLARAR EL GENERADOR DE CLAVES EN MODO DH - Diffie Hellman
		KeyPairGenerator serverKeyGen = KeyPairGenerator.getInstance("DH");
		serverKeyGen.initialize(dhParams, new SecureRandom()); //
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
		KeyPair serverPair = serverKeyGen.generateKeyPair();

		// RECIBE CLAVE PUBLICA DEL CLIENTE
		Key clientePublicKey = (Key) ois.readObject();
		oos.writeObject(serverPair.getPublic());
		
		// ENVIA CLAVE PUBLICA DEL SERVIDOR
		oos.flush();
		System.out.println("Clave publia servidor: " + serverPair.getPublic().toString());
		serverKeyAgree.init(serverPair.getPrivate());
		serverKeyAgree.doPhase(clientePublicKey, true);
		socketServidor.close();
		System.out.println("intercambio exitoso de claves");

	}

}