package org.ripple.bouncycastle.util.test;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.security.securerandom;

public class fixedsecurerandom
    extends securerandom
{
    private byte[]       _data;
    
    private int          _index;
    private int          _intpad;
    
    public fixedsecurerandom(byte[] value)
    {
        this(false, new byte[][] { value });
    }
    
    public fixedsecurerandom(
        byte[][] values)
    {
        this(false, values);
    }
    
    /**
     * pad the data on integer boundaries. this is necessary for the classpath project's biginteger
     * implementation.
     */
    public fixedsecurerandom(
        boolean intpad,
        byte[] value)
    {
        this(intpad, new byte[][] { value });
    }
    
    /**
     * pad the data on integer boundaries. this is necessary for the classpath project's biginteger
     * implementation.
     */
    public fixedsecurerandom(
        boolean intpad,
        byte[][] values)
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();
        
        for (int i = 0; i != values.length; i++)
        {
            try
            {
                bout.write(values[i]);
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("can't save value array.");
            }
        }
        
        _data = bout.tobytearray();
        
        if (intpad)
        {
            _intpad = _data.length % 4;
        }
    }

    public void nextbytes(byte[] bytes)
    {
        system.arraycopy(_data, _index, bytes, 0, bytes.length);
        
        _index += bytes.length;
    }
    
    //
    // classpath's implementation of securerandom doesn't currently go back to nextbytes
    // when next is called. we can't override next as it's a final method.
    //
    public int nextint()
    {
        int val = 0;
        
        val |= nextvalue() << 24;
        val |= nextvalue() << 16;
        
        if (_intpad == 2)
        {
            _intpad--;
        }
        else
        {
            val |= nextvalue() << 8;
        }
        
        if (_intpad == 1)
        {
            _intpad--;
        }
        else
        {
            val |= nextvalue();
        }
        
        return val;
    }
    
    //
    // classpath's implementation of securerandom doesn't currently go back to nextbytes
    // when next is called. we can't override next as it's a final method.
    //
    public long nextlong()
    {
        long val = 0;
        
        val |= (long)nextvalue() << 56;
        val |= (long)nextvalue() << 48;
        val |= (long)nextvalue() << 40;
        val |= (long)nextvalue() << 32;
        val |= (long)nextvalue() << 24;
        val |= (long)nextvalue() << 16;
        val |= (long)nextvalue() << 8;
        val |= (long)nextvalue();
        
        return val;
    }

    public boolean isexhausted()
    {
        return _index == _data.length;
    }

    private int nextvalue()
    {
        return _data[_index++] & 0xff;
    }
}
