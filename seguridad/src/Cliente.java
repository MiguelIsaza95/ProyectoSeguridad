
/**
 * Proyecto chat cifrado seguridad.
 * Universidad Icesi
 * @author Miguel Isaza, Steven Montealegre, Cristian Morales
 * @version: 3/6/2019
 */
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;


/**
 * Esta clase se encarga de generar la clave privada a intercambiar con el servidor para establecer una comunicación
 * Permite el intercambio de mensaje entre clientes.
 * @author Miguel Isaza, Steven Montealegre, Cristian Morales
 *
 */
public class Cliente {

	// Variables para generar la clave publica y privada a intercambiar con el servidor.
	public final static String key = "92AE31A79FEEB2A3";
	public final static String iv = "0123456789ABCDEF";

	private BufferedReader in;
	private PrintWriter out;
	private JFrame frame = new JFrame("Chatter");
	private JTextField textField = new JTextField(40);
	private JTextArea messageArea = new JTextArea(8, 40);

/**
 * Constructor de la clase cliente, se crea la interfaz gráfica para iniciar el chat.
 */
	public Cliente() {
		textField.setEditable(false);
		messageArea.setEditable(false);
		frame.getContentPane().add(textField, "North");
		frame.getContentPane().add(new JScrollPane(messageArea), "Center");
		frame.pack();

		// Add Listeners
		textField.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				// Se escribe el mensaje, se encripta y se envía
				try {
					String mensaje = EncriptacionMensajes.encriptar(key, iv, textField.getText());
					System.out.println("Mensaje cifrado: " + mensaje);
					out.println(mensaje);
					textField.setText("");
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

			}
		});
	}

	/**
	 * Método que se encarga de obtener la dirección IP del servidor con el que se van a intercambiar las claves.
	 * @return Dirección IP del servidor.
	 */
	private String getServerAddress() {
		String ip = JOptionPane.showInputDialog(frame, "Enter IP Address of the Server:", "Welcome to the Chatter",
				JOptionPane.QUESTION_MESSAGE); 
		return ip;
	}

	/**
	 * Método encargado de obtener el nombre del usuario para iniciar el chat.
	 * @return Nombre del usuario que se une al chat
	 */
	private String getName() {
		String name = JOptionPane.showInputDialog(frame, "Choose a screen name:", "Screen name selection",
				JOptionPane.PLAIN_MESSAGE);
		frame.setTitle("Chat: "+ name);
		return name;
	}
/**
 * Aquí se generan la clave a intercambiar con el servidor usando Diffie-Hellman. Además, aquí se habilita 
 * el chat del cliente con el fin de establecer una comunicación con otro usuario, durante la comunicación 
 * todos los mensaje serán encriptados con el algoritmo AES de 128 bits.
 * @throws Exception
 */
	@SuppressWarnings("resource")
	private void run() throws Exception {

		// Make connection and initialize streams
		String serverAddress = getServerAddress();
		Socket socket = new Socket(serverAddress, 9001);
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		out = new PrintWriter(socket.getOutputStream(), true);

		out.println("diffie");

		diffiecliente(serverAddress);

		while (true) {

			// Recibe el nombre del usuario
			String line = in.readLine();
			if (line.startsWith("SUBMITNAME")) {
				
				// Se envía el nombre del usuario
				out.println(getName());

			} else if (line.startsWith("NAMEACCEPTED")) {
				
				// Recibe el nombre del cliente y luego permite escribir
				textField.setEditable(true);
			} else if (line.startsWith("MESSAGE")) {
				String rec = line.substring(8);
				String[] contenidoMensaje = rec.split(":");
				System.out.println("encritptado c:" + contenidoMensaje[1].trim());
				String desen = EncriptacionMensajes.desencriptar(key, iv, contenidoMensaje[1].trim());
				messageArea.append(contenidoMensaje[0] + ": " + desen + "\n");
			}
		}
	}
/**
 * Método encargado de ejecutar el socket del cliente para realizar sus respectivas funcionalidades.
 * @param args
 * @throws Exception
 */
	public static void main(String[] args) throws Exception {
		Cliente client = new Cliente();
		client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		client.frame.setVisible(true);
		client.run();

	}

	/**
	 * Aquí se emplea el algoritmo Diffie-Hellman para el intercambio de claves
	 * @param ip, dirección ip del servidor con quien intercambiará claves.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 */
	public static void diffiecliente(String ip) throws IOException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeyException {

		// Se declaran las variables de las llaves
		BigInteger p;
		BigInteger g;
		
		// Se declaran las variables de lectura, almacenamiento y control
		String parametro;

		// Se abre el puerto al servidor para transmitir
		Socket socketCliente = new Socket(ip, 15210);

		// Crea los flujos de objetos
		ObjectOutputStream oos = new ObjectOutputStream(socketCliente.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(socketCliente.getInputStream());

		// Crea los flujos de escritura y lectura
		BufferedReader inFromServer = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
		BufferedWriter OutFromClient = new BufferedWriter(new OutputStreamWriter(socketCliente.getOutputStream()));

		// Lectura de la orden de inicio del servidor
		parametro = inFromServer.readLine();
		System.out.println("Mensaje del servidor: " + parametro);
		if (parametro.equalsIgnoreCase("GENERAR DH")) {

			// Mensaje de confirmacion al servidor
			OutFromClient.write("LISTO PARA GENERAR DH\n");
			OutFromClient.flush();
		}

		// Lectura del parametro G del servidor
		parametro = inFromServer.readLine();
		System.out.println("Me llega parametro G: " + parametro);
		g = new BigInteger(parametro);

		// Se genera el parametro P del cliente
		SecureRandom secureP = new SecureRandom();
		p = BigInteger.probablePrime(1024, secureP);
		System.out.println("parametro p cliente: " + p.toString());
		// Transmision del parametro P
		OutFromClient.write(p.toString() + "\n");
		OutFromClient.flush();

		// Se usan los parametros G y P para generar la clave
		DHParameterSpec dhParams = new DHParameterSpec(g, p);
		KeyPairGenerator clienteKeyGen = KeyPairGenerator.getInstance("DH");
		clienteKeyGen.initialize(dhParams, new SecureRandom());
		KeyPair clientePair = clienteKeyGen.generateKeyPair();
		System.out.println("clave publica cliente " + clientePair.getPublic());

		// Se obtiene la clave publica y se transmite al servidor
		oos.writeObject(clientePair.getPublic());

		// Se obtiene la clave publica del servidor
		Key serverPublicKey = (Key) ois.readObject();
		System.out.println(serverPublicKey.toString());

		// Se crea el keyagreemente para comprobar las llaves
		KeyAgreement clienteKeyAgree = KeyAgreement.getInstance("DH");
		// Clave privada del cliente
		clienteKeyAgree.init(clientePair.getPrivate());
		// Clave publica del servidor
		clienteKeyAgree.doPhase(serverPublicKey, true);

		socketCliente.close();
		System.out.println("Intercambio de claves exitoso");

	}

}