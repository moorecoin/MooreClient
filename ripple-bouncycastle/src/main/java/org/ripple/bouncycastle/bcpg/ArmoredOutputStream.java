package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;
import java.io.outputstream;
import java.util.enumeration;
import java.util.hashtable;

/**
 * basic output stream.
 */
public class armoredoutputstream
    extends outputstream
{
    private static final byte[] encodingtable =
        {
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v',
            (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6',
            (byte)'7', (byte)'8', (byte)'9',
            (byte)'+', (byte)'/'
        };

    /**
     * encode the input data producing a base 64 encoded byte array.
     */
    private void encode(
        outputstream    out,
        int[]           data,
        int             len)
        throws ioexception
    {
        int    d1, d2, d3;

        switch (len)
        {
        case 0:        /* nothing left to do */
            break;
        case 1:
            d1 = data[0];

            out.write(encodingtable[(d1 >>> 2) & 0x3f]);
            out.write(encodingtable[(d1 << 4) & 0x3f]);
            out.write('=');
            out.write('=');
            break;
        case 2:
            d1 = data[0];
            d2 = data[1];

            out.write(encodingtable[(d1 >>> 2) & 0x3f]);
            out.write(encodingtable[((d1 << 4) | (d2 >>> 4)) & 0x3f]);
            out.write(encodingtable[(d2 << 2) & 0x3f]);
            out.write('=');
            break;
        case 3:
            d1 = data[0];
            d2 = data[1];
            d3 = data[2];

            out.write(encodingtable[(d1 >>> 2) & 0x3f]);
            out.write(encodingtable[((d1 << 4) | (d2 >>> 4)) & 0x3f]);
            out.write(encodingtable[((d2 << 2) | (d3 >>> 6)) & 0x3f]);
            out.write(encodingtable[d3 & 0x3f]);
            break;
        default:
            throw new ioexception("unknown length in encode");
        }
    }

    outputstream    out;
    int[]           buf = new int[3];
    int             bufptr = 0;
    crc24           crc = new crc24();
    int             chunkcount = 0;
    int             lastb;

    boolean         start = true;
    boolean         cleartext = false;
    boolean         newline = false;
    
    string          nl = system.getproperty("line.separator");

    string          type;
    string          headerstart = "-----begin pgp ";
    string          headertail = "-----";
    string          footerstart = "-----end pgp ";
    string          footertail = "-----";

    string          version = "bcpg v1.49";
    
    hashtable       headers = new hashtable();
    
    public armoredoutputstream(
        outputstream    out)
    {
        this.out = out;
        
        if (nl == null)
        {
            nl = "\r\n";
        }
        
        resetheaders();
    }
    
    public armoredoutputstream(
        outputstream    out,
        hashtable       headers)
    {
        this(out);

        enumeration e = headers.keys();
        
        while (e.hasmoreelements())
        {
            object key = e.nextelement();
            
            this.headers.put(key, headers.get(key));
        }
    }
    
    /**
     * set an additional header entry.
     * 
     * @param name the name of the header entry.
     * @param value the value of the header entry.
     */
    public void setheader(
        string name,
        string value)
    {
        this.headers.put(name, value);
    }
    
    /**
     * reset the headers to only contain a version string.
     */
    public void resetheaders()
    {
        headers.clear();
        headers.put("version", version);
    }
    
    /**
     * start a clear text signed message.
     * @param hashalgorithm
     */
    public void begincleartext(
        int    hashalgorithm) 
        throws ioexception
    {
        string    hash;
        
        switch (hashalgorithm)
        {
        case hashalgorithmtags.sha1:
            hash = "sha1";
            break;
        case hashalgorithmtags.sha256:
            hash = "sha256";
            break;
        case hashalgorithmtags.sha384:
            hash = "sha384";
            break;
        case hashalgorithmtags.sha512:
            hash = "sha512";
            break;
        case hashalgorithmtags.md2:
            hash = "md2";
            break;
        case hashalgorithmtags.md5:
            hash = "md5";
            break;
        case hashalgorithmtags.ripemd160:
            hash = "ripemd160";
            break;
        default:
            throw new ioexception("unknown hash algorithm tag in begincleartext: " + hashalgorithm);
        }
        
        string armorhdr = "-----begin pgp signed message-----" + nl;
        string hdrs = "hash: " + hash + nl + nl;
        
        for (int i = 0; i != armorhdr.length(); i++)
        {
            out.write(armorhdr.charat(i));
        }
        
        for (int i = 0; i != hdrs.length(); i++)
        {
            out.write(hdrs.charat(i));
        }
        
        cleartext = true;
        newline = true;
        lastb = 0;
    }
    
    public void endcleartext()
    {
        cleartext = false;
    }
    
    private void writeheaderentry(
        string name,
        string value) 
        throws ioexception
    {
        for (int i = 0; i != name.length(); i++)
        {
            out.write(name.charat(i));
        }
        
        out.write(':');
        out.write(' ');
        
        for (int i = 0; i != value.length(); i++)
        {
            out.write(value.charat(i));
        }

        for (int i = 0; i != nl.length(); i++)
        {
            out.write(nl.charat(i));
        }
    }
    
    public void write(
        int    b)
        throws ioexception
    {
        if (cleartext)
        {
            out.write(b);

            if (newline)
            {
                if (!(b == '\n' && lastb == '\r'))
                {
                    newline = false;
                }
                if (b == '-')
                {
                    out.write(' ');
                    out.write('-');      // dash escape
                }
            }
            if (b == '\r' || (b == '\n' && lastb != '\r'))
            {
                newline = true;
            }
            lastb = b;
            return;
        }
        
        if (start)
        {
            boolean     newpacket = (b & 0x40) != 0;
            int         tag = 0;
            
            if (newpacket)
            {
                tag = b & 0x3f;
            }
            else
            {
                tag = (b & 0x3f) >> 2;
            }

            switch (tag)
            {
            case packettags.public_key:
                type = "public key block";
                break;
            case packettags.secret_key:
                type = "private key block";
                break;
            case packettags.signature:
                type = "signature";
                break;
            default:
                type = "message";
            }
            
            for (int i = 0; i != headerstart.length(); i++)
            {
                out.write(headerstart.charat(i));
            }

            for (int i = 0; i != type.length(); i++)
            {
                out.write(type.charat(i));
            }

            for (int i = 0; i != headertail.length(); i++)
            {
                out.write(headertail.charat(i));
            }

            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charat(i));
            }
          
            writeheaderentry("version", (string)headers.get("version"));

            enumeration e = headers.keys();
            while (e.hasmoreelements())
            {
                string  key = (string)e.nextelement();
                
                if (!key.equals("version"))
                {
                    writeheaderentry(key, (string)headers.get(key));
                }
            }
            
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charat(i));
            }

            start = false;
        }

        if (bufptr == 3)
        {
            encode(out, buf, bufptr);
            bufptr = 0;
            if ((++chunkcount & 0xf) == 0)
            {
                for (int i = 0; i != nl.length(); i++)
                {
                    out.write(nl.charat(i));
                }
            }
        }

        crc.update(b);
        buf[bufptr++] = b & 0xff;
    }
    
    public void flush()
        throws ioexception
    {
    }
    
    /**
     * <b>note</b>: close does nor close the underlying stream. so it is possible to write
     * multiple objects using armoring to a single stream.
     */
    public void close()
        throws ioexception
    {
        if (type != null)
        {
            encode(out, buf, bufptr);
        
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charat(i));
            }
            out.write('=');
        
            int        crcv = crc.getvalue();
        
            buf[0] = ((crcv >> 16) & 0xff);
            buf[1] = ((crcv >> 8) & 0xff);
            buf[2] = (crcv & 0xff);
        
            encode(out, buf, 3);
        
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charat(i));
            }
        
            for (int i = 0; i != footerstart.length(); i++)
            {
                out.write(footerstart.charat(i));
            }
        
            for (int i = 0; i != type.length(); i++)
            {
                out.write(type.charat(i));
            }
        
            for (int i = 0; i != footertail.length(); i++)
            {
                out.write(footertail.charat(i));
            }
        
            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charat(i));
            }
        
            out.flush();
            
            type = null;
            start = true;
        }
    }
}
