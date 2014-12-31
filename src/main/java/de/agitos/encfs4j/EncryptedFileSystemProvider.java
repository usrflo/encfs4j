/*
 * Encrypted Java FileSystem Provider
 * 
 * Copyright 2014 Agitos GmbH, Florian Sager, sager@agitos.de, http://www.agitos.de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * A licence was granted to the ASF by Florian Sager on 31 December 2014
 */
package de.agitos.encfs4j;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import de.agitos.encfs4j.EncryptedFileSystem.EncryptedFileSystemPath;

/*
 * FileSystemProvider implementation that works like a layer above the base file system.
 * File system operations are delegated to the base file system except SeekableByteChannel newByteChannel(...).
 * The latter returns a CipherFileChannel to decrypt/encrypt data on-the-fly.
 * 
 * How-to integrate:

FileSystemProvider provider = new EncryptedFileSystemProvider();
Map<String,String> env = new HashMap<String,String>();
env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM, "AES");
env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM_MODE, "CTR");
env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM_PADDING, "NoPadding");
env.put(EncryptedFileSystemProvider.SECRET_KEY, "1234567890abcdef"); // your 128 bit key
env.put(EncryptedFileSystemProvider.REVERSE_MODE, "true");
env.put(EncryptedFileSystemProvider.FILESYSTEM_ROOT_URI, "file:/my/root-directory-for-encryption/");

// EITHER Syntax A

Path path = Paths.get(URI.create("enc:///my/root-directory-for-encryption/sub/file-to-be-encrypted"));
InputStream inStream = Files.newInputStream(path);
OutputStream outStream = Files.newOutputStream(path);

// OR Syntax B

URI uri = URI.create("enc:///");
fs = provider.newFileSystem(uri, env);
Path path = fs.getPath("/my/root-directory-for-encryption/sub/file-to-be-encrypted");
OutputStream outStream = provider.newOutputStream(path);
InputStream inStream = provider.newInputStream(path);

*/

public class EncryptedFileSystemProvider extends FileSystemProvider {

	public static final String URISCHEME = "enc";
	public static final String URISCHEMESPECPART = "///";

	public static final String CIPHER_ALGORITHM = "CipherAlgorithm";
	public static final String CIPHER_ALGORITHM_MODE = "CipherAlgorithmMode";
	public static final String CIPHER_ALGORITHM_PADDING = "CipherAlgorithmPadding";
	public static final String SECRET_KEY = "SecretKey";
	public static final String FILESYSTEM_ROOT_URI = "FileSystemRootURI";
	public static final String REVERSE_MODE = "ReverseMode";

	private static volatile EncryptedFileSystem encFileSystem;
	private static volatile String cipherTransformation;
	private static volatile SecretKeySpec secretKeySpec;
	private static volatile Path fileSystemRoot;
	private static volatile boolean isReverse;

	public EncryptedFileSystemProvider() {
	}

	@Override
	public String getScheme() {
		return URISCHEME;
	}

	private void assertUriScheme(URI uri) {
		if (!uri.getScheme().equalsIgnoreCase(URISCHEME))
			throw new IllegalArgumentException();
	}

	private void assertUri(URI uri) {
		assertUriScheme(uri);
		if (!uri.getSchemeSpecificPart().equals(URISCHEMESPECPART))
			throw new IllegalArgumentException();
	}

	@Override
	public FileSystem newFileSystem(URI uri, Map<String, ?> env)
			throws IOException {
		assertUri(uri);
		synchronized (EncryptedFileSystemProvider.class) {
			if (encFileSystem != null)
				throw new FileSystemAlreadyExistsException();

			// check environment
			try {
				String cipherAlgorithm = (String) env.get(CIPHER_ALGORITHM);
				if (cipherAlgorithm == null)
					throw new IllegalArgumentException(
							"Missing filesystem variable '" + CIPHER_ALGORITHM
									+ "'");

				String cipherAlgorithmMode = (String) env
						.get(CIPHER_ALGORITHM_MODE);
				if (cipherAlgorithmMode == null)
					throw new IllegalArgumentException(
							"Missing filesystem variable '"
									+ CIPHER_ALGORITHM_MODE + "'");

				String cipherAlgorithmPadding = (String) env
						.get(CIPHER_ALGORITHM_PADDING);
				if (cipherAlgorithmPadding == null)
					throw new IllegalArgumentException(
							"Missing filesystem variable '"
									+ CIPHER_ALGORITHM_PADDING + "'");

				cipherTransformation = cipherAlgorithm + "/"
						+ cipherAlgorithmMode + "/" + cipherAlgorithmPadding;
				Cipher.getInstance(cipherTransformation);
				// FSTODO: cipher.getParameters().getProvider() --> check secret
				// key length ?

				String secretKey = (String) env.get(SECRET_KEY);
				if (secretKey == null)
					throw new IllegalArgumentException(
							"Missing filesystem variable '" + SECRET_KEY + "'");

				secretKeySpec = new SecretKeySpec(secretKey.getBytes(),
						cipherAlgorithm);

				String fileSystemRootString = (String) env
						.get(FILESYSTEM_ROOT_URI);
				if (fileSystemRootString == null)
					fileSystemRootString = "file:/";
				fileSystemRoot = Paths.get(new URI(fileSystemRootString))
						.normalize();
				
				String isReverseString = (String) env.get(REVERSE_MODE);
				isReverse = "true".equalsIgnoreCase(isReverseString);

			} catch (Exception e) {
				throw new IOException(e);
			}

			EncryptedFileSystem result = new EncryptedFileSystem(this,
					FileSystems.getDefault());
			encFileSystem = result;
			return result;
		}
	}

	@Override
	public FileSystem getFileSystem(URI uri) {
		assertUri(uri);
		FileSystem result = encFileSystem;
		if (result == null)
			throw new FileSystemNotFoundException();
		return result;
	}

	@Override
	public Path getPath(URI uri) {
		assertUriScheme(uri);
		if (encFileSystem == null)
			throw new FileSystemNotFoundException();

		// avoid unterminated recursion / to be able to run Paths.get(URI)
		uri = URI.create(encFileSystem.getSubFileSystem().provider()
				.getScheme()
				+ ":" + uri.getSchemeSpecificPart());
		return new EncryptedFileSystemPath(encFileSystem, encFileSystem
				.getSubFileSystem().provider().getPath(uri));
	}

	@Override
	public void setAttribute(Path file, String attribute, Object value,
			LinkOption... options) throws IOException {
		Files.setAttribute(EncryptedFileSystem.dismantle(file), attribute,
				value, options);
	}

	@Override
	public Map<String, Object> readAttributes(Path file, String attributes,
			LinkOption... options) throws IOException {
		return Files.readAttributes(EncryptedFileSystem.dismantle(file),
				attributes, options);
	}

	@Override
	public <V extends FileAttributeView> V getFileAttributeView(Path file,
			Class<V> type, LinkOption... options) {
		return Files.getFileAttributeView(EncryptedFileSystem.dismantle(file),
				type, options);
	}

	@Override
	public <A extends BasicFileAttributes> A readAttributes(Path file,
			Class<A> type, LinkOption... options) throws IOException {
		return Files.readAttributes(EncryptedFileSystem.dismantle(file), type,
				options);
	}

	@Override
	public void delete(Path file) throws IOException {
		Files.delete(EncryptedFileSystem.dismantle(file));
	}

	@Override
	public void createSymbolicLink(Path link, Path target,
			FileAttribute<?>... attrs) throws IOException {
		Files.createSymbolicLink(EncryptedFileSystem.dismantle(link),
				EncryptedFileSystem.dismantle(target), attrs);
	}

	@Override
	public void createLink(Path link, Path existing) throws IOException {
		Files.createLink(EncryptedFileSystem.dismantle(link),
				EncryptedFileSystem.dismantle(existing));
	}

	@Override
	public Path readSymbolicLink(Path link) throws IOException {
		Path target = Files.readSymbolicLink(EncryptedFileSystem
				.dismantle(link));
		return new EncryptedFileSystemPath(encFileSystem, target);
	}

	@Override
	public void copy(Path source, Path target, CopyOption... options)
			throws IOException {
		Files.copy(EncryptedFileSystem.dismantle(source),
				EncryptedFileSystem.dismantle(target), options);
	}

	@Override
	public void move(Path source, Path target, CopyOption... options)
			throws IOException {
		Files.move(EncryptedFileSystem.dismantle(source),
				EncryptedFileSystem.dismantle(target), options);
	}

	private DirectoryStream<Path> mantle(final DirectoryStream<Path> stream) {
		return new DirectoryStream<Path>() {
			@Override
			public Iterator<Path> iterator() {
				final Iterator<Path> itr = stream.iterator();
				return new Iterator<Path>() {
					@Override
					public boolean hasNext() {
						return itr.hasNext();
					}

					@Override
					public Path next() {
						return new EncryptedFileSystemPath(encFileSystem,
								itr.next());
					}

					@Override
					public void remove() {
						itr.remove();
					}
				};
			}

			@Override
			public void close() throws IOException {
				stream.close();
			}
		};
	}

	@Override
	public DirectoryStream<Path> newDirectoryStream(Path dir,
			DirectoryStream.Filter<? super Path> filter) throws IOException {
		return mantle(Files.newDirectoryStream(
				EncryptedFileSystem.dismantle(dir), filter));
	}

	@Override
	public void createDirectory(Path dir, FileAttribute<?>... attrs)
			throws IOException {
		Files.createDirectory(EncryptedFileSystem.dismantle(dir), attrs);
	}

	@Override
	public SeekableByteChannel newByteChannel(Path file,
			Set<? extends OpenOption> options, FileAttribute<?>... attrs)
			throws IOException {
		return new CipherFileChannel(
				EncryptedFileSystem.dismantle(file), cipherTransformation,
				secretKeySpec, fileSystemRoot, isReverse, options, attrs);
	}

	@Override
	public boolean isHidden(Path file) throws IOException {
		return Files.isHidden(EncryptedFileSystem.dismantle(file));
	}

	@Override
	public FileStore getFileStore(Path file) throws IOException {
		return Files.getFileStore(EncryptedFileSystem.dismantle(file));
	}

	@Override
	public boolean isSameFile(Path file, Path other) throws IOException {
		return Files.isSameFile(EncryptedFileSystem.dismantle(file),
				EncryptedFileSystem.dismantle(other));
	}

	@Override
	public void checkAccess(Path file, AccessMode... modes) throws IOException {
		if (modes.length == 0) {
			if (Files.exists(EncryptedFileSystem.dismantle(file)))
				return;
			else
				throw new NoSuchFileException(file.toString());
		}

		// see
		// https://docs.oracle.com/javase/7/docs/api/java/nio/file/spi/FileSystemProvider.html#checkAccess%28java.nio.file.Path,%20java.nio.file.AccessMode...%29
		throw new UnsupportedOperationException("not implemented");
	}
}
