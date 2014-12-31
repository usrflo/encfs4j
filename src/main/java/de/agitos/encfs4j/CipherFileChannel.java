/*
 * Delayed encrypting/decrypting SeekableByteChannel
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * CipherFileChannel has the following properties:
 * 
 * - transparent encryption/decryption of a SeekableByteChannel.
 * 
 * - either read/write encrypted data to/from a persistent file while processing decrypted data (reverse mode off). Sample: you want to read/write encrypted data to your probably insecure local file store.
 *  
 * - or read/write decrypted data to/from a persistent file while processing encrypted data (reverse mode on). Sample: sync locally unencrypted files to a remote store with transparent encryption on the fly.
 * 
 * - encrypted/decrypted temporary data is written to a temp file in the default temporary file directory (e.g. /tmp/). In case of APPEND/WRITE, the data is persisted if you call close(). The required store space for the temp file is equal to the persistent file size.
 * 
 * - the initialization vector (IV) of the encryption is unique per relativeFilename. A relativeFilename is relative to the provided fileSystemRoot. A fileSystemRoot is similar to a mountpoint that contains all files that can be encrypted/decrypted with the same symmetric key.
 */

public class CipherFileChannel implements SeekableByteChannel {

	// path of the underlying file
	private Path path;

	// temp file for random access operations on encrypted/decrypted data
	private File tmpFile;

	// transformed (volatile) file
	private RandomAccessFile trafoFile;

	// persistent file
	private RandomAccessFile persistentFile;

	// transformed (volatile) channel
	private FileChannel trafoChannel;

	// persistent channel
	private FileChannel persistentChannel;

	// mode of operation: if isReverse the the persistent file is unencrypted,
	// else the persistent file is encrypted
	private boolean isReverse;

	// if isReadingRequired then the temp file has to contain transformed data
	private boolean isReadingRequired = true;

	// is the file channel open?
	private boolean isOpen = false;

	// if isModified the persistent file has to be encrypted/decrypted on
	// close()
	private boolean isModified = false;

	// cipher transformation like 'AES'
	private String cipherTransformation;

	// the secret symmetric key
	private SecretKeySpec secretKeySpec;

	// a relative filename to calculate the IV
	private String relativeFilename;

	public CipherFileChannel(Path path, String cipherTransformation,
			SecretKeySpec secretKeySpec, Path fileSystemRoot,
			boolean isReverse, Set<? extends OpenOption> options,
			FileAttribute<?>... attrs) throws IOException {

		this(path, cipherTransformation, secretKeySpec, fileSystemRoot,
				isReverse);

		// FSTODO: more options required?
		if (options.size() > 0 && !options.contains(StandardOpenOption.READ)
				&& !options.contains(StandardOpenOption.APPEND)) {
			this.isReadingRequired = false;
		}
	}

	public CipherFileChannel(Path path, String cipherTransformation,
			SecretKeySpec secretKeySpec, Path fileSystemRoot, boolean isReverse)
			throws IOException {

		try {
			this.path = path.normalize();

			// this.encrypt =
			// "encfs".equals(path.getFileSystem().provider().getScheme());

			this.persistentFile = new RandomAccessFile(path.toFile(), "rw");

			this.persistentChannel = this.persistentFile.getChannel();
			this.isOpen = true;

			this.cipherTransformation = cipherTransformation;
			this.secretKeySpec = secretKeySpec;

			this.relativeFilename = fileSystemRoot.relativize(this.path)
					.toString();

			this.isReverse = isReverse;

		} catch (FileNotFoundException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	public boolean isOpen() {
		return this.isOpen;
	}

	public long position() throws IOException {
		// as long as the transformed channel is not initialized get the
		// position from the persistent channel
		return this.trafoChannel == null ? this.persistentChannel.position()
				: this.trafoChannel.position();
	}

	public SeekableByteChannel position(long newPosition) throws IOException {
		// as long as the transformed channel is not initialized set the
		// position on the persistent channel
		SeekableByteChannel ch = this.trafoChannel == null ? this.persistentChannel
				.position(newPosition) : this.trafoChannel
				.position(newPosition);
		return this;
	}

	public int read(ByteBuffer dst) throws IOException {

		if (this.trafoChannel == null) {
			// create the transformed temp file now
			this.initTrafoChannel();
		}

		return this.trafoChannel.read(dst);
	}

	public long size() throws IOException {
		// as long as the transformed channel is not initialized get the
		// information from the persistent channel
		return this.trafoChannel == null ? this.persistentChannel.size()
				: this.trafoChannel.size();
	}

	public SeekableByteChannel truncate(long length) throws IOException {
		// as long as the transformed channel is not initialized truncate the
		// persistent channel
		SeekableByteChannel ch = this.trafoChannel == null ? this.persistentChannel
				.truncate(length) : this.trafoChannel.truncate(length);
		return this;
	}

	public int write(ByteBuffer src) throws IOException {

		if (this.trafoChannel == null) {
			// create the transformed temp file now
			this.initTrafoChannel();
		}

		int bytesWritten = this.trafoChannel.write(src);
		if (!this.isModified)
			this.isModified = bytesWritten > 0;
		return bytesWritten;
	}

	public void close() throws IOException {

		if (this.trafoChannel != null) {
			this.closeTrafoChannel();
			this.trafoChannel.close();
			this.trafoFile.close();
		}

		this.persistentChannel.close();
		this.persistentFile.close();

		this.isOpen = false;
	}

	private void initTrafoChannel() throws IOException {
		try {
			// create temp file in default temp directory
			this.tmpFile = File.createTempFile("encfs-", ".dat");
			this.tmpFile.deleteOnExit();

			if (this.isReadingRequired) {
				// encrypt/decrypt everything from persistentChannel if the
				// persistent file content should be read
				Cipher cipher = this
						.getCipher(this.isReverse ? Cipher.ENCRYPT_MODE
								: Cipher.DECRYPT_MODE);

				this.persistentChannel.position(0);

				// this is where encryption/decryption takes place in the
				// beginning based on CipherOutputStream
				this.copyStream(
						Channels.newInputStream(this.persistentChannel),
						new CipherOutputStream(new FileOutputStream(
								this.tmpFile), cipher));
			}

			this.trafoFile = new RandomAccessFile(this.tmpFile, "rw");
			this.trafoChannel = this.trafoFile.getChannel();

			// read/write on trafoChannel now

		} catch (InvalidKeyException | NoSuchAlgorithmException
				| DigestException | NoSuchPaddingException
				| InvalidAlgorithmParameterException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	private void closeTrafoChannel() throws IOException {

		try {

			if (!this.isModified)
				// nothing to write back to the persistent file
				return;

			// reset persistentChannel, encrypt/decrypt everything in
			// trafoChannel to
			// persistentChannel
			this.persistentChannel.truncate(0);
			Cipher cipher = this.getCipher(this.isReverse ? Cipher.DECRYPT_MODE
					: Cipher.ENCRYPT_MODE);

			this.trafoChannel.position(0);

			// this is where encryption/decryption takes place in the end based
			// on CipherOutputStream
			this.copyStream(
					Channels.newInputStream(this.trafoChannel),
					new CipherOutputStream(Channels
							.newOutputStream(this.persistentChannel), cipher));

			// finally remove the temp file
			this.tmpFile.delete();

		} catch (InvalidKeyException | NoSuchAlgorithmException
				| DigestException | NoSuchPaddingException
				| InvalidAlgorithmParameterException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	private void copyStream(InputStream from, OutputStream to)
			throws IOException {

		byte[] buffer = new byte[4096];
		int bytes_read;

		while ((bytes_read = from.read(buffer)) != -1)
			// Read until EOF
			to.write(buffer, 0, bytes_read);

		to.flush();

		// streams have to remain open
	}

	private Cipher getCipher(int cipherMode) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, DigestException {

		Cipher cipher = Cipher.getInstance(this.cipherTransformation);

		// calculate a file specific IV based on the unique relative filename
		byte[] iv = new byte[cipher.getBlockSize()];
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(this.relativeFilename.getBytes());
		md.digest(iv, 0, cipher.getBlockSize());
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// load the mode, symmetric key and IV into the Cipher
		cipher.init(cipherMode, this.secretKeySpec, ivParameterSpec);
		return cipher;

	}
}
