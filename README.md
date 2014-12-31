encfs4j
=======

encfs4j (Encrypted File System for Java) is a minimalist [Java FileSystem](http://openjdk.java.net/projects/nio/javadoc/java/nio/file/FileSystem.html) implementation that encrypts/decrypts file content on-the-fly.
Using the FileSystem implementation you can abstract encryption operations from random file access. Extending existing applications with encrypted file storage is simplified by this means of transparency.

The implementation is tested with - but not limited to - AES block cipher (128-bit symmetric key) with CTR mode (AES/CTR/NoPadding).

Only file content is encrypted, there is no encryption of directory or file names. Each file is encrypted with a different IV ([initialization vector](http://en.wikipedia.org/wiki/Initialization_vector)) that depends on its unique path relative to the filesystem root directory.
The root directory is similar to a mountpoint that contains all directories and files that are subject to the encryption. To keep IVs unique please assure to use different symmetric keys for different encrypted file systems. In other words, use a specific symmetric key for a filesystem root directory only.

The fact that file names remain unencrypted allows an attacker to guess its content. Please be aware that this might allow to decrypt the content of the single file that contains the guessed content.
There is currently no planning to add encryption of directory or file names because the current use cases require these names to be available in cleartext for direct access.

encfs4j requires [OpenJDK 1.7 or later](http://openjdk.java.net/) or [Oracle JDK 7](http://java.oracle.com)

Two modes of operation
----------------------

- **default**: persist encrypted files while processing unencrypted files.
  *Sample:* an existing Java application is extended to read/write encrypted files from/to disk without changing existing stream operations.

- **reverse**: persist unencrypted files while processing encrypted files.
  *Sample:* sync locally unencrypted data to a remote file store with file content being encrypted on-the-fly. 


Warning
-------

This software is still unstable and there might be data corruption bugs hiding. So use it carefully at your own risk.

If you encounter any problems please create an issue on Github.


Sample Integration
------------------

```Java
FileSystemProvider provider = new EncryptedFileSystemProvider();
Map<String,String> env = new HashMap<String,String>();
env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM, "AES");
env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM_MODE, "CTR");
env.put(EncryptedFileSystemProvider.CIPHER_ALGORITHM_PADDING, "NoPadding");
env.put(EncryptedFileSystemProvider.SECRET_KEY, "1234567890abcdef"); // your 128 bit key
env.put(EncryptedFileSystemProvider.REVERSE_MODE, "true"); // "false" or remove for default mode 
env.put(EncryptedFileSystemProvider.FILESYSTEM_ROOT_URI, "file:/my/root-directory-for-encryption/"); // base directory for file system operations
```

Either use URIs (with scheme enc:///) to refer to the encrypted file system:

```Java
Path path = Paths.get(URI.create("enc:///my/root-directory-for-encryption/sub/file-to-be-encrypted"));
InputStream inStream = Files.newInputStream(path);
OutputStream outStream = Files.newOutputStream(path);
```

Or directly refer to the provider:

```Java
URI uri = URI.create("enc:///");
fs = provider.newFileSystem(uri, env);
Path path = fs.getPath("/my/root-directory-for-encryption/sub/file-to-be-encrypted");
OutputStream outStream = provider.newOutputStream(path);
InputStream inStream = provider.newInputStream(path);
```

License
-------

Copyright (C) 2014 Agitos GmbH, Florian Sager, sager@agitos.de, http://www.agitos.de

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

A licence was granted to the ASF by Florian Sager on 31 December 2014
