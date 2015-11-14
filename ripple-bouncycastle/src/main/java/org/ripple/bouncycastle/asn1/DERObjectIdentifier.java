package org.ripple.bouncycastle.asn1;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.math.biginteger;

import org.ripple.bouncycastle.util.arrays;

public class derobjectidentifier
    extends asn1primitive
{
    string identifier;

    private byte[] body;

    /**
     * return an oid from the passed in object
     *
     * @throws illegalargumentexception if the object cannot be converted.
     */
    public static asn1objectidentifier getinstance(
        object obj)
    {
        if (obj == null || obj instanceof asn1objectidentifier)
        {
            return (asn1objectidentifier)obj;
        }

        if (obj instanceof derobjectidentifier)
        {
            return new asn1objectidentifier(((derobjectidentifier)obj).getid());
        }

        if (obj instanceof asn1encodable && ((asn1encodable)obj).toasn1primitive() instanceof asn1objectidentifier)
        {
            return (asn1objectidentifier)((asn1encodable)obj).toasn1primitive();
        }

        if (obj instanceof byte[])
        {
            return asn1objectidentifier.fromoctetstring((byte[])obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return an object identifier from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws illegalargumentexception if the tagged object cannot
     * be converted.
     */
    public static asn1objectidentifier getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derobjectidentifier)
        {
            return getinstance(o);
        }
        else
        {
            return asn1objectidentifier.fromoctetstring(asn1octetstring.getinstance(obj.getobject()).getoctets());
        }
    }

    private static final long long_limit = (long.max_value >> 7) - 0x7f;

    derobjectidentifier(
        byte[] bytes)
    {
        stringbuffer objid = new stringbuffer();
        long value = 0;
        biginteger bigvalue = null;
        boolean first = true;

        for (int i = 0; i != bytes.length; i++)
        {
            int b = bytes[i] & 0xff;

            if (value <= long_limit)
            {
                value += (b & 0x7f);
                if ((b & 0x80) == 0)             // end of number reached
                {
                    if (first)
                    {
                        if (value < 40)
                        {
                            objid.append('0');
                        }
                        else if (value < 80)
                        {
                            objid.append('1');
                            value -= 40;
                        }
                        else
                        {
                            objid.append('2');
                            value -= 80;
                        }
                        first = false;
                    }

                    objid.append('.');
                    objid.append(value);
                    value = 0;
                }
                else
                {
                    value <<= 7;
                }
            }
            else
            {
                if (bigvalue == null)
                {
                    bigvalue = biginteger.valueof(value);
                }
                bigvalue = bigvalue.or(biginteger.valueof(b & 0x7f));
                if ((b & 0x80) == 0)
                {
                    if (first)
                    {
                        objid.append('2');
                        bigvalue = bigvalue.subtract(biginteger.valueof(80));
                        first = false;
                    }

                    objid.append('.');
                    objid.append(bigvalue);
                    bigvalue = null;
                    value = 0;
                }
                else
                {
                    bigvalue = bigvalue.shiftleft(7);
                }
            }
        }

        this.identifier = objid.tostring();
        this.body = arrays.clone(bytes);
    }

    public derobjectidentifier(
        string identifier)
    {
        if (identifier == null)
        {
            throw new illegalargumentexception("'identifier' cannot be null");
        }
        if (!isvalididentifier(identifier))
        {
            throw new illegalargumentexception("string " + identifier + " not an oid");
        }

        this.identifier = identifier;
    }

    derobjectidentifier(derobjectidentifier oid, string branchid)
    {
        if (!isvalidbranchid(branchid, 0))
        {
            throw new illegalargumentexception("string " + branchid + " not a valid oid branch");
        }

        this.identifier = oid.getid() + "." + branchid;
    }

    public string getid()
    {
        return identifier;
    }

    private void writefield(
        bytearrayoutputstream out,
        long fieldvalue)
    {
        byte[] result = new byte[9];
        int pos = 8;
        result[pos] = (byte)((int)fieldvalue & 0x7f);
        while (fieldvalue >= (1l << 7))
        {
            fieldvalue >>= 7;
            result[--pos] = (byte)((int)fieldvalue & 0x7f | 0x80);
        }
        out.write(result, pos, 9 - pos);
    }

    private void writefield(
        bytearrayoutputstream out,
        biginteger fieldvalue)
    {
        int bytecount = (fieldvalue.bitlength() + 6) / 7;
        if (bytecount == 0)
        {
            out.write(0);
        }
        else
        {
            biginteger tmpvalue = fieldvalue;
            byte[] tmp = new byte[bytecount];
            for (int i = bytecount - 1; i >= 0; i--)
            {
                tmp[i] = (byte)((tmpvalue.intvalue() & 0x7f) | 0x80);
                tmpvalue = tmpvalue.shiftright(7);
            }
            tmp[bytecount - 1] &= 0x7f;
            out.write(tmp, 0, tmp.length);
        }
    }

    private void dooutput(bytearrayoutputstream aout)
    {
        oidtokenizer tok = new oidtokenizer(identifier);
        int first = integer.parseint(tok.nexttoken()) * 40;

        string secondtoken = tok.nexttoken();
        if (secondtoken.length() <= 18)
        {
            writefield(aout, first + long.parselong(secondtoken));
        }
        else
        {
            writefield(aout, new biginteger(secondtoken).add(biginteger.valueof(first)));
        }

        while (tok.hasmoretokens())
        {
            string token = tok.nexttoken();
            if (token.length() <= 18)
            {
                writefield(aout, long.parselong(token));
            }
            else
            {
                writefield(aout, new biginteger(token));
            }
        }
    }

    protected synchronized byte[] getbody()
    {
        if (body == null)
        {
            bytearrayoutputstream bout = new bytearrayoutputstream();

            dooutput(bout);

            body = bout.tobytearray();
        }

        return body;
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
        throws ioexception
    {
        int length = getbody().length;

        return 1 + streamutil.calculatebodylength(length) + length;
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        byte[] enc = getbody();

        out.write(bertags.object_identifier);
        out.writelength(enc.length);
        out.write(enc);
    }

    public int hashcode()
    {
        return identifier.hashcode();
    }

    boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof derobjectidentifier))
        {
            return false;
        }

        return identifier.equals(((derobjectidentifier)o).identifier);
    }

    public string tostring()
    {
        return getid();
    }

    private static boolean isvalidbranchid(
        string branchid, int start)
    {
        boolean periodallowed = false;

        int pos = branchid.length();
        while (--pos >= start)
        {
            char ch = branchid.charat(pos);

            // todo leading zeroes?
            if ('0' <= ch && ch <= '9')
            {
                periodallowed = true;
                continue;
            }

            if (ch == '.')
            {
                if (!periodallowed)
                {
                    return false;
                }

                periodallowed = false;
                continue;
            }

            return false;
        }

        return periodallowed;
    }

    private static boolean isvalididentifier(
        string identifier)
    {
        if (identifier.length() < 3 || identifier.charat(1) != '.')
        {
            return false;
        }

        char first = identifier.charat(0);
        if (first < '0' || first > '2')
        {
            return false;
        }

        return isvalidbranchid(identifier, 2);
    }

    private static asn1objectidentifier[][] cache = new asn1objectidentifier[256][];

    static asn1objectidentifier fromoctetstring(byte[] enc)
    {
        if (enc.length < 3)
        {
            return new asn1objectidentifier(enc);
        }

        int idx1 = enc[enc.length - 2] & 0xff;
        // in this case top bit is always zero
        int idx2 = enc[enc.length - 1] & 0x7f;

        asn1objectidentifier possiblematch;

        synchronized (cache)
        {
            asn1objectidentifier[] first = cache[idx1];
            if (first == null)
            {
                first = cache[idx1] = new asn1objectidentifier[128];
            }

            possiblematch = first[idx2];
            if (possiblematch == null)
            {
                return first[idx2] = new asn1objectidentifier(enc);
            }

            if (arrays.areequal(enc, possiblematch.getbody()))
            {
                return possiblematch;
            }

            idx1 = (idx1 + 1) & 0xff;
            first = cache[idx1];
            if (first == null)
            {
                first = cache[idx1] = new asn1objectidentifier[128];
            }

            possiblematch = first[idx2];
            if (possiblematch == null)
            {
                return first[idx2] = new asn1objectidentifier(enc);
            }

            if (arrays.areequal(enc, possiblematch.getbody()))
            {
                return possiblematch;
            }

            idx2 = (idx2 + 1) & 0x7f;
            possiblematch = first[idx2];
            if (possiblematch == null)
            {
                return first[idx2] = new asn1objectidentifier(enc);
            }
        }

        if (arrays.areequal(enc, possiblematch.getbody()))
        {
            return possiblematch;
        }

        return new asn1objectidentifier(enc);
    }
}
