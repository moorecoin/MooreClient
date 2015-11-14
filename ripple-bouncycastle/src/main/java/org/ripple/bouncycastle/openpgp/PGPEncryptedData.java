package org.ripple.bouncycastle.openpgp;

import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

import org.ripple.bouncycastle.bcpg.inputstreampacket;
import org.ripple.bouncycastle.bcpg.symmetricencintegritypacket;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.util.arrays;

public abstract class pgpencrypteddata
    implements symmetrickeyalgorithmtags
{
    protected class truncatedstream extends inputstream
    {
        int[]         lookahead = new int[22];
        int           bufptr;
        inputstream   in;
        
        truncatedstream(
            inputstream    in) 
            throws ioexception
        {
            for (int i = 0; i != lookahead.length; i++)
            {
                if ((lookahead[i] = in.read()) < 0)
                {
                    throw new eofexception();
                }
            }
            
            bufptr = 0;
            this.in = in;
        }

        public int read() 
            throws ioexception
        {
            int    ch = in.read();
            
            if (ch >= 0)
            {
                int    c = lookahead[bufptr];
                
                lookahead[bufptr] = ch;
                bufptr = (bufptr + 1) % lookahead.length;
                
                return c;
            }
            
            return -1;
        }
        
        int[] getlookahead()
        {
            int[]    tmp = new int[lookahead.length];
            int    count = 0;
            
            for (int i = bufptr; i != lookahead.length; i++)
            {
                tmp[count++] = lookahead[i];
            }
            for (int i = 0; i != bufptr; i++)
            {
                tmp[count++] = lookahead[i];
            }
            
            return tmp;
        }
    }
    
    inputstreampacket        encdata;
    inputstream              encstream;
    truncatedstream          truncstream;
    pgpdigestcalculator      integritycalculator;

    pgpencrypteddata(
        inputstreampacket    encdata)
    {
        this.encdata = encdata;
    }
    
    /**
     * return the raw input stream for the data stream.
     * 
     * @return inputstream
     */
    public inputstream getinputstream()
    {
        return encdata.getinputstream();
    }
    
    /**
     * return true if the message is integrity protected.
     * @return true if there is a modification detection code package associated with this stream
     */
    public boolean isintegrityprotected()
    {
        return (encdata instanceof symmetricencintegritypacket);
    }
    
    /**
     * note: this can only be called after the message has been read.
     * 
     * @return true if the message verifies, false otherwise.
     * @throws pgpexception if the message is not integrity protected.
     */
    public boolean verify()
        throws pgpexception, ioexception
    {
        if (!this.isintegrityprotected())
        {
            throw new pgpexception("data not integrity protected.");
        }

        //
        // make sure we are at the end.
        //
        while (encstream.read() >= 0)
        {
            // do nothing
        }

        //
        // process the mdc packet
        //
        int[] lookahead = truncstream.getlookahead();

        outputstream dout = integritycalculator.getoutputstream();

        dout.write((byte)lookahead[0]);
        dout.write((byte)lookahead[1]);

        byte[] digest = integritycalculator.getdigest();
        byte[] streamdigest = new byte[digest.length];

        for (int i = 0; i != streamdigest.length; i++)
        {
            streamdigest[i] = (byte)lookahead[i + 2];
        }

        return arrays.constanttimeareequal(digest, streamdigest);
    }
}
