package de.agitos.encfs4j;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashMap;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

// FSTODO: test with AES/GCM/NoPadding (128-bit block cipher)

public class EncryptedFileSystemTest {

	private static File persistentFile;
	private static FileSystemProvider provider;
	private static FileSystem fs;
	private static String testString = "To provide all citizens under general suspicion, secretly tap off their data, thereby violating national law and international agreements and to cover this defect rather than to clarify, is a crime of state security forces against their own people and foreigners that will not end sooner, than by the consistent use of encryption technology no longer acceptable monitoring results are achieved, tax dollars for improper supervision are withdrawn and all perpetrators were held personally accountable.";

	@BeforeClass
	public static void init() throws IOException, URISyntaxException {

		persistentFile = File.createTempFile("EncryptedFileSystem-", ".test");
		persistentFile.deleteOnExit();

		// According to
		// https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher

		provider = new EncryptedFileSystemProvider();
		Map<String, Object> env = new HashMap<String, Object>();
		env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM, "AES");
		env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM_MODE, "CTR");
		env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM_PADDING,
				"NoPadding");
		// 128 bit key
		env.put(EncryptedFileSystemProvider.SECRET_KEY, "f31BmUS)&?O!19W:".getBytes());
		env.put(EncryptedFileSystemProvider.FILESYSTEM_ROOT_URI, "file:///"
				+ persistentFile.getParent().replaceAll("\\\\", "/"));
		// env.put(EncryptedFileSystemProvider.REVERSE_MODE, "true");

		URI uri = URI.create("enc:///");
		fs = provider.newFileSystem(uri, env);
	}

	@Test
	public void testSyntaxA() throws IOException {

		Path path = fs.getPath(persistentFile.getAbsolutePath().replaceAll("\\\\", "/"));
		if (!Files.exists(path)) {
			Files.createFile(path);
		}
		OutputStream outStream = provider.newOutputStream(path);
		outStream.write(testString.getBytes());
		outStream.close();

		InputStream inStream = provider.newInputStream(path);
		BufferedReader in = new BufferedReader(new InputStreamReader(inStream));

		StringBuilder buf = new StringBuilder();
		String line = null;
		while ((line = in.readLine()) != null) {
			buf.append(line);
		}
		inStream.close();

		assertEquals(testString, buf.toString());
	}

	@Test
	public void testSyntaxB() throws IOException {

		Path path = Paths.get(URI.create("enc:///"
				+ persistentFile.getAbsolutePath().replaceAll("\\\\", "/")));
		if (!Files.exists(path)) {
			Files.createFile(path);
		}

		OutputStream outStream = Files.newOutputStream(path);
		outStream.write(testString.getBytes());
		outStream.close();

		InputStream inStream = Files.newInputStream(path);
		BufferedReader in = new BufferedReader(new InputStreamReader(inStream));

		StringBuilder buf = new StringBuilder();
		String line = null;
		while ((line = in.readLine()) != null) {
			buf.append(line);
		}
		inStream.close();

		assertEquals(testString, buf.toString());
	}

	@Test
	public void testMove() throws IOException {
		// Files.move(tempFile, path, StandardCopyOption.ATOMIC_MOVE);

		Path path = Paths.get(URI.create("enc:///"
				+ persistentFile.getAbsolutePath().replaceAll("\\\\", "/")));
		if (!Files.exists(path)) {
			Files.createFile(path);
		}

		OutputStream outStream = Files.newOutputStream(path);
		outStream.write(testString.getBytes());
		outStream.close();

		File anotherFile = File.createTempFile("EncryptedFileSystem-",
				".testmove");
		anotherFile.deleteOnExit();
		Path anotherPath = Paths.get(URI.create("file:///"
				+ anotherFile.getAbsolutePath().replaceAll("\\\\", "/")));

		Files.move(path, anotherPath, StandardCopyOption.COPY_ATTRIBUTES,
				StandardCopyOption.REPLACE_EXISTING);

		InputStream inStream = Files.newInputStream(anotherPath);
		BufferedReader in = new BufferedReader(new InputStreamReader(inStream));

		StringBuilder buf = new StringBuilder();
		String line = null;
		while ((line = in.readLine()) != null) {
			buf.append(line);
		}
		inStream.close();

		assertEquals(testString, buf.toString());
	}

	@AfterClass
	public static void finish() {
		System.out.println("Test text EncryptedFileSystemTest:");
		System.out.println(testString);
	}

}
