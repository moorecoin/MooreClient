package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

import org.ripple.bouncycastle.util.io.streams;

public abstract class dergenerator
    extends asn1generator
{       
    private boolean      _tagged = false;
    private boolean      _isexplicit;
    private int          _tagno;
    
    protected dergenerator(
        outputstream out)
    {
        super(out);
    }

    public dergenerator(
        outputstream out,
        int          tagno,
        boolean      isexplicit)
    { 
        super(out);
        
        _tagged = true;
        _isexplicit = isexplicit;
        _tagno = tagno;
    }

    private void writelength(
        outputstream out,
        int          length)
        throws ioexception
    {
        if (length > 127)
        {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0)
            {
                size++;
            }

            out.write((byte)(size | 0x80));

            for (int i = (size - 1) * 8; i >= 0; i -= 8)
            {
                out.write((byte)(length >> i));
            }
        }
        else
        {
            out.write((byte)length);
        }
    }

    void writederencoded(
        outputstream out,
        int          tag,
        byte[]       bytes)
        throws ioexception
    {
        out.write(tag);
        writelength(out, bytes.length);
        out.write(bytes);
    }

    void writederencoded(
        int       tag,
        byte[]    bytes)
        throws ioexception
    {
        if (_tagged)
        {
            int tagnum = _tagno | bertags.tagged;
            
            if (_isexplicit)
            {
                int newtag = _tagno | bertags.constructed | bertags.tagged;

                bytearrayoutputstream bout = new bytearrayoutputstream();
                
                writederencoded(bout, tag, bytes);
                
                writederencoded(_out, newtag, bout.tobytearray());
            }
            else
            {   
                if ((tag & bertags.constructed) != 0)
                {
                    writederencoded(_out, tagnum | bertags.constructed, bytes);
                }
                else
                {
                    writederencoded(_out, tagnum, bytes);
                }
            }
        }
        else
        {
            writederencoded(_out, tag, bytes);
        }
    }
    
    void writederencoded(
        outputstream out,
        int          tag,
        inputstream  in)
        throws ioexception
    {
        writederencoded(out, tag, streams.readall(in));
    }
}
