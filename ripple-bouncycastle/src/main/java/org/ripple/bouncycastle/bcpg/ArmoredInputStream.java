package org.ripple.bouncycastle.bcpg;

import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;
import java.util.vector;

/**
 * reader for base64 armored objects - read the headers and then start returning
 * bytes when the data is reached. an ioexception is thrown if the crc check
 * fails.
 */
public class armoredinputstream
    extends inputstream
{
    /*
     * set up the decoding table.
     */
    private static final byte[] decodingtable;

    static
    {
        decodingtable = new byte[128];

        for (int i = 'a'; i <= 'z'; i++)
        {
            decodingtable[i] = (byte)(i - 'a');
        }

        for (int i = 'a'; i <= 'z'; i++)
        {
            decodingtable[i] = (byte)(i - 'a' + 26);
        }

        for (int i = '0'; i <= '9'; i++)
        {
            decodingtable[i] = (byte)(i - '0' + 52);
        }

        decodingtable['+'] = 62;
        decodingtable['/'] = 63;
    }

    /**
     * decode the base 64 encoded input data.
     *
     * @return the offset the data starts in out.
     */
    private int decode(
        int      in0,
        int      in1,
        int      in2,
        int      in3,
        int[]    out)
        throws eofexception
    {
        int    b1, b2, b3, b4;

        if (in3 < 0)
        {
            throw new eofexception("unexpected end of file in armored stream.");
        }

        if (in2 == '=')
        {
            b1 = decodingtable[in0] &0xff;
            b2 = decodingtable[in1] & 0xff;

            out[2] = ((b1 << 2) | (b2 >> 4)) & 0xff;

            return 2;
        }
        else if (in3 == '=')
        {
            b1 = decodingtable[in0];
            b2 = decodingtable[in1];
            b3 = decodingtable[in2];

            out[1] = ((b1 << 2) | (b2 >> 4)) & 0xff;
            out[2] = ((b2 << 4) | (b3 >> 2)) & 0xff;

            return 1;
        }
        else
        {
            b1 = decodingtable[in0];
            b2 = decodingtable[in1];
            b3 = decodingtable[in2];
            b4 = decodingtable[in3];

            out[0] = ((b1 << 2) | (b2 >> 4)) & 0xff;
            out[1] = ((b2 << 4) | (b3 >> 2)) & 0xff;
            out[2] = ((b3 << 6) | b4) & 0xff;

            return 0;
        }
    }

    inputstream    in;
    boolean        start = true;
    int[]          outbuf = new int[3];
    int            bufptr = 3;
    crc24          crc = new crc24();
    boolean        crcfound = false;
    boolean        hasheaders = true;
    string         header = null;
    boolean        newlinefound = false;
    boolean        cleartext = false;
    boolean        restart = false;
    vector         headerlist= new vector();
    int            lastc = 0;
    boolean        isendofstream;
    
    /**
     * create a stream for reading a pgp armoured message, parsing up to a header 
     * and then reading the data that follows.
     * 
     * @param in
     */
    public armoredinputstream(
        inputstream    in) 
        throws ioexception
    {
        this(in, true);
    }

    /**
     * create an armoured input stream which will assume the data starts
     * straight away, or parse for headers first depending on the value of 
     * hasheaders.
     * 
     * @param in
     * @param hasheaders true if headers are to be looked for, false otherwise.
     */
    public armoredinputstream(
        inputstream    in,
        boolean        hasheaders) 
        throws ioexception
    {
        this.in = in;
        this.hasheaders = hasheaders;
        
        if (hasheaders)
        {
            parseheaders();
        }

        start = false;
    }
    
    public int available()
        throws ioexception
    {
        return in.available();
    }
    
    private boolean parseheaders()
        throws ioexception
    {
        header = null;
        
        int        c;
        int        last = 0;
        boolean    headerfound = false;
        
        headerlist = new vector();
        
        //
        // if restart we already have a header
        //
        if (restart)
        {
            headerfound = true;
        }
        else
        {
            while ((c = in.read()) >= 0)
            {
                if (c == '-' && (last == 0 || last == '\n' || last == '\r'))
                {
                    headerfound = true;
                    break;
                }
    
                last = c;
            }
        }

        if (headerfound)
        {
            stringbuffer    buf = new stringbuffer("-");
            boolean         eolreached = false;
            boolean         crlf = false;
            
            if (restart)    // we've had to look ahead two '-'
            {
                buf.append('-');
            }
            
            while ((c = in.read()) >= 0)
            {
                if (last == '\r' && c == '\n')
                {
                    crlf = true;
                }
                if (eolreached && (last != '\r' && c == '\n'))
                {
                    break;
                }
                if (eolreached && c == '\r')
                {
                    break;
                }
                if (c == '\r' || (last != '\r' && c == '\n'))
                {
                    string line = buf.tostring();
                    if (line.trim().length() == 0)
                    {
                        break;
                    }
                    headerlist.addelement(line);
                    buf.setlength(0);
                }

                if (c != '\n' && c != '\r')
                {
                    buf.append((char)c);
                    eolreached = false;
                }
                else
                {
                    if (c == '\r' || (last != '\r' && c == '\n'))
                    {
                        eolreached = true;
                    }
                }
                
                last = c;
            }
            
            if (crlf)
            {
                in.read(); // skip last \n
            }
        }
        
        if (headerlist.size() > 0)
        {
            header = (string)headerlist.elementat(0);
        }
        
        cleartext = "-----begin pgp signed message-----".equals(header);
        newlinefound = true;

        return headerfound;
    }

    /**
     * @return true if we are inside the clear text section of a pgp
     * signed message.
     */
    public boolean iscleartext()
    {
        return cleartext;
    }

    /**
     * @return true if the stream is actually at end of file.
     */
    public boolean isendofstream()
    {
        return isendofstream;
    }

    /**
     * return the armor header line (if there is one)
     * @return the armor header line, null if none present.
     */
    public string    getarmorheaderline()
    {
        return header;
    }
    
    /**
     * return the armor headers (the lines after the armor header line),
     * @return an array of armor headers, null if there aren't any.
     */
    public string[] getarmorheaders()
    {
        if (headerlist.size() <= 1)
        {
            return null;
        }
        
        string[]    hdrs = new string[headerlist.size() - 1];
        
        for (int i = 0; i != hdrs.length; i++)
        {
            hdrs[i] = (string)headerlist.elementat(i + 1);
        }
        
        return hdrs;
    }
    
    private int readignorespace() 
        throws ioexception
    {
        int    c = in.read();
        
        while (c == ' ' || c == '\t')
        {
            c = in.read();
        }
        
        return c;
    }
    
    public int read()
        throws ioexception
    {
        int    c;

        if (start)
        {
            if (hasheaders)
            {
                parseheaders();
            }

            crc.reset();
            start = false;
        }
        
        if (cleartext)
        {
            c = in.read();

            if (c == '\r' || (c == '\n' && lastc != '\r'))
            {
                newlinefound = true;
            }
            else if (newlinefound && c == '-')
            {
                c = in.read();
                if (c == '-')            // a header, not dash escaped
                {
                    cleartext = false;
                    start = true;
                    restart = true;
                }
                else                   // a space - must be a dash escape
                {
                    c = in.read();
                }
                newlinefound = false;
            }
            else
            {
                if (c != '\n' && lastc != '\r')
                {
                    newlinefound = false;
                }
            }
            
            lastc = c;

            if (c < 0)
            {
                isendofstream = true;
            }
            
            return c;
        }

        if (bufptr > 2 || crcfound)
        {
            c = readignorespace();
            
            if (c == '\r' || c == '\n')
            {
                c = readignorespace();
                
                while (c == '\n' || c == '\r')
                {
                    c = readignorespace();
                }

                if (c < 0)                // eof
                {
                    isendofstream = true;
                    return -1;
                }

                if (c == '=')            // crc reached
                {
                    bufptr = decode(readignorespace(), readignorespace(), readignorespace(), readignorespace(), outbuf);
                    if (bufptr == 0)
                    {
                        int i = ((outbuf[0] & 0xff) << 16)
                                | ((outbuf[1] & 0xff) << 8)
                                | (outbuf[2] & 0xff);

                        crcfound = true;

                        if (i != crc.getvalue())
                        {
                            throw new ioexception("crc check failed in armored message.");
                        }
                        return read();
                    }
                    else
                    {
                        throw new ioexception("no crc found in armored message.");
                    }
                }
                else if (c == '-')        // end of record reached
                {
                    while ((c = in.read()) >= 0)
                    {
                        if (c == '\n' || c == '\r')
                        {
                            break;
                        }
                    }

                    if (!crcfound)
                    {
                        throw new ioexception("crc check not found.");
                    }

                    crcfound = false;
                    start = true;
                    bufptr = 3;

                    if (c < 0)
                    {
                        isendofstream = true;
                    }

                    return -1;
                }
                else                   // data
                {
                    bufptr = decode(c, readignorespace(), readignorespace(), readignorespace(), outbuf);
                }
            }
            else
            {
                if (c >= 0)
                {
                    bufptr = decode(c, readignorespace(), readignorespace(), readignorespace(), outbuf);
                }
                else
                {
                    isendofstream = true;
                    return -1;
                }
            }
        }

        c = outbuf[bufptr++];

        crc.update(c);

        return c;
    }
    
    public void close()
        throws ioexception
    {
        in.close();
    }
}
