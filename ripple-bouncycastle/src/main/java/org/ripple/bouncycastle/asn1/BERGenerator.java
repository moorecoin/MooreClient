package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

public class bergenerator
    extends asn1generator
{
    private boolean      _tagged = false;
    private boolean      _isexplicit;
    private int          _tagno;
    
    protected bergenerator(
        outputstream out)
    {
        super(out);
    }

    public bergenerator(
        outputstream out,
        int tagno,
        boolean isexplicit) 
    {
        super(out);
        
        _tagged = true;
        _isexplicit = isexplicit;
        _tagno = tagno;
    }

    public outputstream getrawoutputstream()
    {
        return _out;
    }
    
    private void writehdr(
        int tag)
        throws ioexception
    {
        _out.write(tag);
        _out.write(0x80);
    }
    
    protected void writeberheader(
        int tag) 
        throws ioexception
    {
        if (_tagged)
        {
            int tagnum = _tagno | bertags.tagged;

            if (_isexplicit)
            {
                writehdr(tagnum | bertags.constructed);
                writehdr(tag);
            }
            else
            {   
                if ((tag & bertags.constructed) != 0)
                {
                    writehdr(tagnum | bertags.constructed);
                }
                else
                {
                    writehdr(tagnum);
                }
            }
        }
        else
        {
            writehdr(tag);
        }
    }
    
    protected void writeberbody(
        inputstream contentstream)
        throws ioexception
    {
        int ch;
        
        while ((ch = contentstream.read()) >= 0)
        {
            _out.write(ch);
        }
    }

    protected void writeberend()
        throws ioexception
    {
        _out.write(0x00);
        _out.write(0x00);
        
        if (_tagged && _isexplicit)  // write extra end for tag header
        {
            _out.write(0x00);
            _out.write(0x00);
        }
    }
}
