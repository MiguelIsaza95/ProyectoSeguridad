
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class ChatClient {

	public final static String key = "ESTEESELVECTORPR";
	public final static String iv = "ESTEESELVECTORPR";

	private BufferedReader in;
	private PrintWriter out;
	private JFrame frame = new JFrame("Chatter");
	private JTextField textField = new JTextField(40);
	private JTextArea messageArea = new JTextArea(8, 40);


	public ChatClient() {

		textField.setEditable(false);
		messageArea.setEditable(false);
		frame.getContentPane().add(textField, "North");
		frame.getContentPane().add(new JScrollPane(messageArea), "Center");
		frame.pack();

		// Add Listeners
		textField.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				// escribe y lo envia

				// aqui cifra

				try {
					String envio = StringEncrypt.encrypt(key, iv, textField.getText());
					System.out.println("cifrado " + envio);
					out.println(envio);
					textField.setText("");
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

			}
		});
	}

	private String getServerAddress() {
		return JOptionPane.showInputDialog(frame, "Enter IP Address of the Server:", "Welcome to the Chatter",
				JOptionPane.QUESTION_MESSAGE);
	}

	private String getName() {
		return JOptionPane.showInputDialog(frame, "Choose a screen name:", "Screen name selection",
				JOptionPane.PLAIN_MESSAGE);
	}

	private void run() throws Exception {

		// Make connection and initialize streams
		String serverAddress = getServerAddress();
		Socket socket = new Socket(serverAddress, 9001);
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		out = new PrintWriter(socket.getOutputStream(), true);

		out.println("diffie");

		diffiecliente(serverAddress);

		while (true) {

			// recibe
			String line = in.readLine();
			if (line.startsWith("SUBMITNAME")) {
				// envia el nbombre
				out.println(getName());

			} else if (line.startsWith("NAMEACCEPTED")) {
				// recibe el nombre del cliente y luego permite escribir
				textField.setEditable(true);
			} else if (line.startsWith("MESSAGE")) {
				String rec = line.substring(8);
				String[] epa = rec.split(":");
				System.out.println("encritptado serivido:" + epa[1].trim());
				String desen = StringEncrypt.decrypt(key, iv, epa[1].trim());
				messageArea.append(epa[0] + ": " + desen + "\n");
			}
		}
	}

	public static void main(String[] args) throws Exception {
		ChatClient client = new ChatClient();
		client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		client.frame.setVisible(true);
		client.run();

	}

	public static void diffiecliente(String ip) throws IOException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeyException {

		// Se declaran las variables de las llaves
		BigInteger p;
		BigInteger g;

		// Se declara la clase para desencriptar

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

		// Genera la clave secreta
		byte[] clienteSharedSecret = clienteKeyAgree.generateSecret();
		SecretKeySpec claveCliente = new SecretKeySpec(clienteSharedSecret, 0, 16, "AES");

		socketCliente.close();
		System.out.println("intercambio exitoso cliente======================");

	}

}