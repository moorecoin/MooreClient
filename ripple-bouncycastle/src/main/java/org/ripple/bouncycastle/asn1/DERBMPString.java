package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

import org.ripple.bouncycastle.util.arrays;

/**
 * der bmpstring object.
 */
public class derbmpstring
    extends asn1primitive
    implements asn1string
{
    private char[]  string;

    /**
     * return a bmp string from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static derbmpstring getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof derbmpstring)
        {
            return (derbmpstring)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (derbmpstring)frombytearray((byte[])obj);
            }
            catch (exception e)
            {
                throw new illegalargumentexception("encoding error in getinstance: " + e.tostring());
            }
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * return a bmp string from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the tagged object cannot
     *              be converted.
     */
    public static derbmpstring getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        asn1primitive o = obj.getobject();

        if (explicit || o instanceof derbmpstring)
        {
            return getinstance(o);
        }
        else
        {
            return new derbmpstring(asn1octetstring.getinstance(o).getoctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    derbmpstring(
        byte[]   string)
    {
        char[]  cs = new char[string.length / 2];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)((string[2 * i] << 8) | (string[2 * i + 1] & 0xff));
        }

        this.string = cs;
    }

    derbmpstring(char[] string)
    {
        this.string = string;
    }

    /**
     * basic constructor
     */
    public derbmpstring(
        string   string)
    {
        this.string = string.tochararray();
    }

    public string getstring()
    {
        return new string(string);
    }

    public string tostring()
    {
        return getstring();
    }

    public int hashcode()
    {
        return arrays.hashcode(string);
    }

    protected boolean asn1equals(
        asn1primitive o)
    {
        if (!(o instanceof derbmpstring))
        {
            return false;
        }

        derbmpstring  s = (derbmpstring)o;

        return arrays.areequal(string, s.string);
    }

    boolean isconstructed()
    {
        return false;
    }

    int encodedlength()
    {
        return 1 + streamutil.calculatebodylength(string.length * 2) + (string.length * 2);
    }

    void encode(
        asn1outputstream out)
        throws ioexception
    {
        out.write(bertags.bmp_string);
        out.writelength(string.length * 2);

        for (int i = 0; i != string.length; i++)
        {
            char c = string[i];

            out.write((byte)(c >> 8));
            out.write((byte)c);
        }
    }
}
