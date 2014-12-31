package de.agitos.encfs4j;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class CipherFileChannelTest {
	
	private static File persistentFile;
	private static String cipherTransformation = "AES/CTR/NoPadding";
	private static SecretKeySpec secretKeySpec = new SecretKeySpec("gP1;5otOHqd#kuci".getBytes(), "AES");
	private static String testString = "Alle Bürger unter Generalverdacht zu stellen, heimlich deren Daten abzugreifen, dabei gegen nationales Recht und internationale Abkommen zu verstoßen und diesen Mißstand zu vertuschen statt aufzuklären, ist ein Verbrechen staatlicher Sicherheitsorgane gegen das eigene Volk und andere Völker, das nicht eher enden wird, bis durch den konsequenten Einsatz von Verschlüsselungstechnik keine Überwachungserfolge mehr erzielt werden, Steuergelder für unsachgemäße Überwachung zurückgezogen und alle Täter persönlich zur Rechenschaft gezogen wurden.";
	private static int testStringLength = testString.getBytes().length;

	@BeforeClass
	public static void init() throws IOException {
		persistentFile = File.createTempFile("CipherFileChannel-", ".test");
		persistentFile.deleteOnExit();
	}

	@Test
	public void test1ReverseWrite() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException {

		CipherFileChannel fc = new CipherFileChannel(Paths.get(persistentFile.getAbsolutePath()), cipherTransformation, secretKeySpec, Paths.get(persistentFile.getParent()), true);
    	
    	ByteBuffer buf = ByteBuffer.allocate(testStringLength);
    	/*
    	fc.read(buf);
    	fc.position(0);
    	buf.clear();
    	*/
    	buf.put(testString.getBytes());
    	buf.flip();
    	fc.write(buf);
    	fc.close();
	}
	
	@Test
	public void test2DefaultRead() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException {

		CipherFileChannel fc = new CipherFileChannel(Paths.get(persistentFile.getAbsolutePath()), cipherTransformation, secretKeySpec, Paths.get(persistentFile.getParent()), false);

		ByteBuffer buf = ByteBuffer.allocate(testStringLength);
    	fc.read(buf);
    	fc.close();
    	
    	buf.flip();

    	byte[] dst = new byte[testStringLength];

    	buf.get(dst);
    	
    	assertEquals(testString, new String(dst));
	}
	
	@AfterClass
	public static void finish() {
		System.out.println("Test text CipherFileChannelTest:");
		System.out.println(testString);
	}

}
