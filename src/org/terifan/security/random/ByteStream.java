package org.terifan.security.random;

import java.util.function.Consumer;
import java.util.stream.BaseStream;


public interface ByteStream extends BaseStream<Byte, ByteStream>
{
	byte[] toArray();

	void forEach(Consumer<Byte> aConsumer);
}
