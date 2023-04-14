package org.terifan.security.random;

import java.io.ByteArrayOutputStream;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.function.Consumer;


abstract class BytePipeline implements ByteStream
{
	private Runnable mCloseHandler;
	abstract boolean tryAdvance(Consumer<Byte> aConsumer);


	public abstract long estimateSize();


	private Byte next;


	@Override
	public byte[] toArray()
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (int i = 0; tryAdvance(v -> next = v); i++)
		{
			baos.write(0xff & next);
		}
		return baos.toByteArray();
	}


	@Override
	public void forEach(Consumer<Byte> aConsumer)
	{
		while (tryAdvance(aConsumer))
		{
		}
	}


	@Override
	public Iterator<Byte> iterator()
	{
		return new Iterator<Byte>()
		{
			@Override
			public boolean hasNext()
			{
				if (next != null)
				{
					return true;
				}
				return tryAdvance(aT -> next = aT);
			}


			@Override
			public Byte next()
			{
				Byte o = next;
				next = null;
				return o;
			}
		};
	}


	@Override
	public Spliterator<Byte> spliterator()
	{
		throw new UnsupportedOperationException();
	}


	@Override
	public boolean isParallel()
	{
		return false;
	}


	@Override
	public ByteStream sequential()
	{
		return this;
	}


	@Override
	public ByteStream parallel()
	{
		return this;
	}


	@Override
	public ByteStream unordered()
	{
		return this;
	}


	@Override
	public ByteStream onClose(Runnable aCloseHandler)
	{
		mCloseHandler = aCloseHandler;
		return this;
	}


	@Override
	public void close()
	{
		if (mCloseHandler != null)
		{
			mCloseHandler.run();
			mCloseHandler = null;
		}
	}
}
