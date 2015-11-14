package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.io.streams;

public class derbitstring
    extends asn1primitive
    implements asn1string
{
    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    
    protected byte[]      data;
    protected int         padbits;

    /**
     * return the correct number of pad bits for a bit string defined in
     * a 32 bit constant
     */
    static protected int getpadbits(
        int bitstring)
    {
        int val = 0;
        for (int i = 3; i >= 0; i--) 
        {
            //
            // this may look a little odd, but if it isn't done like this pre jdk1.2
            // jvm's break!
            //
            if (i != 0)
            {
                if ((bitstring >> (i * 8)) != 0) 
                {
                    val = (bitstring >> (i * 8)) & 0xff;
                    break;
                }
            }
            else
            {
                if (bitstring != 0)
                {
                    val = bitstring & 0xff;
                    break;
                }
            }
        }
 
        if (val == 0)
        {
            return 7;
        }


        int bits = 1;

        while (((val <<= 1) & 0xff) != 0)
        {
            bits++;
        }

        return 8 - bits;
    }

    /**
     * return the correct number of bytes for a bit string defined in
     * a 32 bit constant
     */
    static protected byte[] getbytes(int bitstring)
    {
        int bytes = 4;
        for (int i = 3; i >= 1; i--)
        {
            if ((bitstring & (0xff << (i * 8))) != 0)
            {
                break;
            }
            bytes--;
        }
        
        byte[] result = new byte[bytes];
        for (int i = 0; i < bytes; i++)
        {
            result[i] = (byte) ((bitstring >> (i * 8)) & 0xff);
        }

        return result;
    }

    /**
     * return a bit string from the passed in object
     *
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static derbitstring getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof derbitstring)
        {
            return (derbitstring)obj;
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return a bit string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *               be converted.
     */
    public static derbitstring getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derbitstring)
        {
            return getinstance(o);
        }
        else
        {
            return fromoctetstring(((asn1octetstring)o).getoctets());
        }
    }
    
    protected derbitstring(
        byte    data,
        int     padbits)
    {
        this.data = new byte[1];
        this.data[0] = data;
        this.padbits = padbits;
    }

    /**
     * @param data the octets making up the bit string.
     * @param padbits the number of extra bits at the end of the string.
     */
    public derbitstring(
        byte[]  data,
        int     padbits)
    {
        this.data = data;
        this.padbits = padbits;
    }

    public derbitstring(
        byte[]  data)
    {
        this(data, 0);
    }

    public derbitstring(
        int value)
    {
        this.data = getbytes(value);
        this.padbits = getpadbits(value);
    }

    public derbitstring(
        asn1encodable obj)
        throws ioexception
    {
        this.data = obj.toasn1primitive().getencoded(asn1encoding.der);
        this.padbits = 0;
    }

    public byte[] getbytes()
    {
        return data;
    }

    public int getpadbits()
    {
        return padbits;
    }


    /**
     * @return the value of the bit string as an int (truncating if necessary)
     */
    public int intvalue()
    {
        int value = 0;
        
        for (int i = 0; i != data.length && i != 4; i++)
        {
            value |= (data[i] & 0xff) << (8 * i);
        }
        
        return value;
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        return 1 + streamutil.calculatebodylength(data.length + 1) + data.length + 1;
    }

    void encode(
        asn1outputstream  out)
        throws ioexception
    {
        byte[]  bytes = new byte[getbytes().length + 1];

        bytes[0] = (byte)getpadbits();
        system.arraycopy(getbytes(), 0, bytes, 1, bytes.length - 1);

        out.writeencoded(bertags.bit_string, bytes);
    }

    public int hashcode()
    {
        return padbits ^ arrays.hashcode(data);
    }

    protected boolean asn1equals(
        asn1primitive  o)
    {
        if (!(o instanceof derbitstring))
        {
            return false;
        }

        derbitstring other = (derbitstring)o;

        return this.padbits == other.padbits
            && arrays.areequal(this.data, other.data);
    }

    public string getstring()
    {
        stringbuffer          buf = new stringbuffer("#");
        bytearrayoutputstream bout = new bytearrayoutputstream();
        asn1outputstream      aout = new asn1outputstream(bout);
        
        try
        {
            aout.writeobject(this);
        }
        catch (ioexception e)
        {
           throw new runtimeexception("internal error encoding bitstring");
        }
        
        byte[]    string = bout.tobytearray();
        
        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }
        
        return buf.tostring();
    }

    public string tostring()
    {
        return getstring();
    }

    static derbitstring fromoctetstring(byte[] bytes)
    {
        if (bytes.length < 1)
        {
            throw new illegalargumentexception("truncated bit string detected");
        }

        int padbits = bytes[0];
        byte[] data = new byte[bytes.length - 1];

        if (data.length != 0)
        {
            system.arraycopy(bytes, 1, data, 0, bytes.length - 1);
        }

        return new derbitstring(data, padbits);
    }

    static derbitstring frominputstream(int length, inputstream stream)
        throws ioexception
    {
        if (length < 1)
        {
            throw new illegalargumentexception("truncated bit string detected");
        }

        int padbits = stream.read();
        byte[] data = new byte[length - 1];

        if (data.length != 0)
        {
            if (streams.readfully(stream, data) != data.length)
            {
                throw new eofexception("eof encountered in middle of bit string");
            }
        }

        return new derbitstring(data, padbits);
    }
}
