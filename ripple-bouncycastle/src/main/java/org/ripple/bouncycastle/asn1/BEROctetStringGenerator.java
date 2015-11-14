package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.outputstream;

public class beroctetstringgenerator
    extends bergenerator
{
    public beroctetstringgenerator(outputstream out) 
        throws ioexception
    {
        super(out);
        
        writeberheader(bertags.constructed | bertags.octet_string);
    }

    public beroctetstringgenerator(
        outputstream out,
        int tagno,
        boolean isexplicit) 
        throws ioexception
    {
        super(out, tagno, isexplicit);
        
        writeberheader(bertags.constructed | bertags.octet_string);
    }
    
    public outputstream getoctetoutputstream()
    {
        return getoctetoutputstream(new byte[1000]); // limit for cer encoding.
    }

    public outputstream getoctetoutputstream(
        byte[] buf)
    {
        return new bufferedberoctetstream(buf);
    }
   
    private class bufferedberoctetstream
        extends outputstream
    {
        private byte[] _buf;
        private int    _off;
        private deroutputstream _derout;

        bufferedberoctetstream(
            byte[] buf)
        {
            _buf = buf;
            _off = 0;
            _derout = new deroutputstream(_out);
        }
        
        public void write(
            int b)
            throws ioexception
        {
            _buf[_off++] = (byte)b;

            if (_off == _buf.length)
            {
                deroctetstring.encode(_derout, _buf);
                _off = 0;
            }
        }

        public void write(byte[] b, int off, int len) throws ioexception
        {
            while (len > 0)
            {
                int numtocopy = math.min(len, _buf.length - _off);
                system.arraycopy(b, off, _buf, _off, numtocopy);

                _off += numtocopy;
                if (_off < _buf.length)
                {
                    break;
                }

                deroctetstring.encode(_derout, _buf);
                _off = 0;

                off += numtocopy;
                len -= numtocopy;
            }
        }

        public void close() 
            throws ioexception
        {
            if (_off != 0)
            {
                byte[] bytes = new byte[_off];
                system.arraycopy(_buf, 0, bytes, 0, _off);
                
                deroctetstring.encode(_derout, bytes);
            }
            
             writeberend();
        }
    }
}
