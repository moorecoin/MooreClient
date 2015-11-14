package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;

/**
 * base class for an application specific object
 */
public class derapplicationspecific 
    extends asn1primitive
{
    private final boolean   isconstructed;
    private final int       tag;
    private final byte[]    octets;

    derapplicationspecific(
        boolean isconstructed,
        int     tag,
        byte[]  octets)
    {
        this.isconstructed = isconstructed;
        this.tag = tag;
        this.octets = octets;
    }

    public derapplicationspecific(
        int    tag,
        byte[] octets)
    {
        this(false, tag, octets);
    }

    public derapplicationspecific(
        int                  tag, 
        asn1encodable object)
        throws ioexception 
    {
        this(true, tag, object);
    }

    public derapplicationspecific(
        boolean      explicit,
        int          tag,
        asn1encodable object)
        throws ioexception
    {
        asn1primitive primitive = object.toasn1primitive();

        byte[] data = primitive.getencoded(asn1encoding.der);

        this.isconstructed = explicit || (primitive instanceof asn1set || primitive instanceof asn1sequence);
        this.tag = tag;

        if (explicit)
        {
            this.octets = data;
        }
        else
        {
            int lenbytes = getlengthofheader(data);
            byte[] tmp = new byte[data.length - lenbytes];
            system.arraycopy(data, lenbytes, tmp, 0, tmp.length);
            this.octets = tmp;
        }
    }

    public derapplicationspecific(int tagno, asn1encodablevector vec)
    {
        this.tag = tagno;
        this.isconstructed = true;
        bytearrayoutputstream bout = new bytearrayoutputstream();

        for (int i = 0; i != vec.size(); i++)
        {
            try
            {
                bout.write(((asn1object)vec.get(i)).getencoded(asn1encoding.der));
            }
            catch (ioexception e)
            {
                throw new asn1parsingexception("malformed object: " + e, e);
            }
        }
        this.octets = bout.tobytearray();
    }

    public static derapplicationspecific getinstance(object obj)
    {
        if (obj == null || obj instanceof derapplicationspecific)
        {
            return (derapplicationspecific)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return derapplicationspecific.getinstance(asn1primitive.frombytearray((byte[])obj));
            }
            catch (ioexception e)
            {
                throw new illegalargumentexception("failed to construct object from byte[]: " + e.getmessage());
            }
        }
        else if (obj instanceof asn1encodable)
        {
            asn1primitive primitive = ((asn1encodable)obj).toasn1primitive();

            if (primitive instanceof asn1sequence)
            {
                return (derapplicationspecific)primitive;
            }
        }

        throw new illegalargumentexception("unknown object in getinstance: " + obj.getclass().getname());
    }

    private int getlengthofheader(byte[] data)
    {
        int length = data[1] & 0xff; // todo: assumes 1 byte tag

        if (length == 0x80)
        {
            return 2;      // indefinite-length encoding
        }

        if (length > 127)
        {
            int size = length & 0x7f;

            // note: the invalid long form "0xff" (see x.690 8.1.3.5c) will be caught here
            if (size > 4)
            {
                throw new illegalstateexception("der length more than 4 bytes: " + size);
            }

            return size + 2;
        }

        return 2;
    }

    public boolean isconstructed()
    {
        return isconstructed;
    }
    
    public byte[] getcontents()
    {
        return octets;
    }
    
    public int getapplicationtag() 
    {
        return tag;
    }

    /**
     * return the enclosed object assuming explicit tagging.
     *
     * @return  the resulting object
     * @throws ioexception if reconstruction fails.
     */
    public asn1primitive getobject()
        throws ioexception 
    {
        return new asn1inputstream(getcontents()).readobject();
    }

    /**
     * return the enclosed object assuming implicit tagging.
     *
     * @param dertagno the type tag that should be applied to the object's contents.
     * @return  the resulting object
     * @throws ioexception if reconstruction fails.
     */
    public asn1primitive getobject(int dertagno)
        throws ioexception
    {
        if (dertagno >= 0x1f)
        {
            throw new ioexception("unsupported tag number");
        }

        byte[] orig = this.getencoded();
        byte[] tmp = replacetagnumber(dertagno, orig);

        if ((orig[0] & bertags.constructed) != 0)
        {
            tmp[0] |= bertags.constructed;
        }

        return new asn1inputstream(tmp).readobject();
    }

    int encodedlength()
        throws ioexception
    {
        return streamutil.calculatetaglength(tag) + streamutil.calculatebodylength(octets.length) + octets.length;
    }

    /* (non-javadoc)
     * @see org.bouncycastle.asn1.asn1primitive#encode(org.bouncycastle.asn1.deroutputstream)
     */
    void encode(asn1outputstream out) throws ioexception
    {
        int classbits = bertags.application;
        if (isconstructed)
        {
            classbits |= bertags.constructed;
        }

        out.writeencoded(classbits, tag, octets);
    }
    
    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof derapplicationspecific))
        {
            return false;
        }

        derapplicationspecific other = (derapplicationspecific)o;

        return isconstructed == other.isconstructed
            && tag == other.tag
            && arrays.areequal(octets, other.octets);
    }

    public int hashcode()
    {
        return (isconstructed ? 1 : 0) ^ tag ^ arrays.hashcode(octets);
    }

    private byte[] replacetagnumber(int newtag, byte[] input)
        throws ioexception
    {
        int tagno = input[0] & 0x1f;
        int index = 1;
        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagno == 0x1f)
        {
            tagno = 0;

            int b = input[index++] & 0xff;

            // x.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // note: -1 will pass
            {
                throw new asn1parsingexception("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0))
            {
                tagno |= (b & 0x7f);
                tagno <<= 7;
                b = input[index++] & 0xff;
            }

            tagno |= (b & 0x7f);
        }

        byte[] tmp = new byte[input.length - index + 1];

        system.arraycopy(input, index, tmp, 1, tmp.length - 1);

        tmp[0] = (byte)newtag;

        return tmp;
    }
}
