/*
 * Encrypted Java FileSystem
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
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.spi.FileSystemProvider;
import java.util.Iterator;
import java.util.Set;

/*
 * FileSystem implementation that works like a layer above the base file system.
 * File system operations are delegated to the base file system except Path operations.
 */

class EncryptedFileSystem extends FileSystem {
	private final FileSystemProvider provider;
	private final FileSystem subFileSystem;

	EncryptedFileSystem(FileSystemProvider provider, FileSystem subFileSystem) {
		this.provider = provider;
		this.subFileSystem = subFileSystem;
	}

	@Override
	public FileSystemProvider provider() {
		return provider;
	}

	@Override
	public void close() throws IOException {
		subFileSystem.close();
	}

	@Override
	public boolean isOpen() {
		return subFileSystem.isOpen();
	}

	@Override
	public boolean isReadOnly() {
		return subFileSystem.isReadOnly();
	}

	@Override
	public String getSeparator() {
		return subFileSystem.getSeparator();
	}

	@Override
	public Iterable<Path> getRootDirectories() {
		final Iterable<Path> roots = subFileSystem.getRootDirectories();
		return new Iterable<Path>() {
			@Override
			public Iterator<Path> iterator() {
				final Iterator<Path> itr = roots.iterator();
				return new Iterator<Path>() {
					@Override
					public boolean hasNext() {
						return itr.hasNext();
					}

					@Override
					public Path next() {
						return new EncryptedFileSystemPath(subFileSystem,
								itr.next());
					}

					@Override
					public void remove() {
						itr.remove();
					}
				};
			}
		};
	}

	@Override
	public Iterable<FileStore> getFileStores() {
		return subFileSystem.getFileStores();
	}

	@Override
	public Set<String> supportedFileAttributeViews() {
		return subFileSystem.supportedFileAttributeViews();
	}

	@Override
	public Path getPath(String first, String... more) {
		return new EncryptedFileSystemPath(this, subFileSystem.getPath(first,
				more));
	}

	@Override
	public PathMatcher getPathMatcher(String syntaxAndPattern) {
		final PathMatcher matcher = subFileSystem
				.getPathMatcher(syntaxAndPattern);
		return new PathMatcher() {
			@Override
			public boolean matches(Path path) {
				return matcher.matches(dismantle(path));
			}
		};
	}

	@Override
	public UserPrincipalLookupService getUserPrincipalLookupService() {
		return subFileSystem.getUserPrincipalLookupService();
	}

	@Override
	public WatchService newWatchService() throws IOException {
		throw new UnsupportedOperationException();
	}

	public FileSystem getSubFileSystem() {
		return this.subFileSystem;
	}

	static Path dismantle(Path mantle) {
		if (mantle == null)
			throw new NullPointerException();
		if (!(mantle instanceof EncryptedFileSystemPath))
			throw new ProviderMismatchException();
		return ((EncryptedFileSystemPath) mantle).subFSPath;
	}

	static class EncryptedFileSystemPath implements Path {
		private final FileSystem subFS;
		private final Path subFSPath;

		EncryptedFileSystemPath(FileSystem subFS, Path subFSPath) {
			this.subFS = subFS;
			this.subFSPath = subFSPath;
		}

		@Override
		public FileSystem getFileSystem() {
			return subFS;
		}

		@Override
		public Path getParent() {
			return mantle(subFSPath.getParent());
		}

		@Override
		public Path getRoot() {
			return mantle(subFSPath.getRoot());
		}

		@Override
		public Path getFileName() {
			return mantle(subFSPath.getFileName());
		}

		@Override
		public Path getName(int index) {
			return mantle(subFSPath.getName(index));
		}

		@Override
		public int getNameCount() {
			return subFSPath.getNameCount();
		}

		@Override
		public Path subpath(int beginIndex, int endIndex) {
			return mantle(subFSPath.subpath(beginIndex, endIndex));
		}

		@Override
		public boolean isAbsolute() {
			return subFSPath.isAbsolute();
		}

		@Override
		public boolean startsWith(Path other) {
			return subFSPath.startsWith(dismantle(other));
		}

		@Override
		public boolean startsWith(String other) {
			return subFSPath.startsWith(other);
		}

		@Override
		public boolean endsWith(Path other) {
			return subFSPath.endsWith(dismantle(other));
		}

		@Override
		public boolean endsWith(String other) {
			return subFSPath.endsWith(other);
		}

		@Override
		public Path normalize() {
			return mantle(subFSPath.normalize());
		}

		@Override
		public Path resolve(Path other) {
			return mantle(subFSPath.resolve(dismantle(other)));
		}

		@Override
		public Path resolve(String other) {
			return mantle(subFSPath.resolve(other));
		}

		@Override
		public Path resolveSibling(Path other) {
			return mantle(subFSPath.resolveSibling(dismantle(other)));
		}

		@Override
		public Path resolveSibling(String other) {
			return mantle(subFSPath.resolveSibling(other));
		}

		@Override
		public Path relativize(Path other) {
			return mantle(subFSPath.relativize(dismantle(other)));
		}

		@Override
		public int compareTo(Path other) {
			return subFSPath.compareTo(dismantle(other));
		}

		@Override
		public boolean equals(Object other) {
			if (!(other instanceof EncryptedFileSystemPath))
				return false;
			return subFSPath.equals(dismantle((EncryptedFileSystemPath) other));
		}

		@Override
		public int hashCode() {
			return subFSPath.hashCode();
		}

		@Override
		public Path toAbsolutePath() {
			return mantle(subFSPath.toAbsolutePath());
		}

		@Override
		public Path toRealPath(LinkOption... options) throws IOException {
			return mantle(subFSPath.toRealPath(options));
		}

		@Override
		public File toFile() {
			return subFSPath.toFile();
		}

		@Override
		public URI toUri() {
			String ssp = subFSPath.toUri().getSchemeSpecificPart();
			return URI.create(subFS.provider().getScheme() + ":" + ssp);
		}

		@Override
		public Iterator<Path> iterator() {
			final Iterator<Path> itr = subFSPath.iterator();
			return new Iterator<Path>() {
				@Override
				public boolean hasNext() {
					return itr.hasNext();
				}

				@Override
				public Path next() {
					return mantle(itr.next());
				}

				@Override
				public void remove() {
					itr.remove();
				}
			};
		}

		@Override
		public WatchKey register(WatchService watcher,
				WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) {
			throw new UnsupportedOperationException("not implemented");
		}

		@Override
		public WatchKey register(WatchService watcher,
				WatchEvent.Kind<?>... events) {
			throw new UnsupportedOperationException("not implemented");
		}

		private Path mantle(Path path) {
			return (path != null) ? new EncryptedFileSystemPath(subFS, path)
					: null;
		}

		@Override
		public String toString() {
			return subFSPath.toString();
		}
	}
}
