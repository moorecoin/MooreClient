package org.ripple.bouncycastle.jce;

import java.io.ioexception;
import java.security.principal;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.x509name;

/**
 * a general extension of x509name with a couple of extra methods and
 * constructors.
 * <p>
 * objects of this type can be created from certificates and crls using the
 * principalutil class.
 * </p>
 * @see org.ripple.bouncycastle.jce.principalutil
 */
public class x509principal
    extends x509name
    implements principal
{
    private static asn1sequence readsequence(
        asn1inputstream ain)
        throws ioexception
    {
        try
        {
            return asn1sequence.getinstance(ain.readobject());
        }
        catch (illegalargumentexception e)
        {
            throw new ioexception("not an asn.1 sequence: " + e);
        }
    }

    /**
     * constructor from an encoded byte array.
     */
    public x509principal(
        byte[]  bytes)
        throws ioexception
    {
        super(readsequence(new asn1inputstream(bytes)));
    }

    /**
     * constructor from an x509name object.
     */
    public x509principal(
        x509name  name)
    {
        super((asn1sequence)name.toasn1primitive());
    }

     /**
     * constructor from an x509name object.
     */
    public x509principal(
        x500name name)
    {
        super((asn1sequence)name.toasn1primitive());
    }

    /**
     * constructor from a table of attributes.
     * <p>
     * it's is assumed the table contains oid/string pairs.
     */
    public x509principal(
        hashtable  attributes)
    {
        super(attributes);
    }

    /**
     * constructor from a table of attributes and a vector giving the
     * specific ordering required for encoding or conversion to a string.
     * <p>
     * it's is assumed the table contains oid/string pairs.
     */
    public x509principal(
        vector      ordering,
        hashtable   attributes)
    {
        super(ordering, attributes);
    }

    /**
     * constructor from a vector of attribute values and a vector of oids.
     */
    public x509principal(
        vector      oids,
        vector      values)
    {
        super(oids, values);
    }

    /**
     * takes an x509 dir name as a string of the format "c=au,st=victoria", or
     * some such, converting it into an ordered set of name attributes.
     */
    public x509principal(
        string  dirname)
    {
        super(dirname);
    }

    /**
     * takes an x509 dir name as a string of the format "c=au,st=victoria", or
     * some such, converting it into an ordered set of name attributes. if reverse
     * is false the dir name will be encoded in the order of the (name, value) pairs 
     * presented, otherwise the encoding will start with the last (name, value) pair
     * and work back.
     */
    public x509principal(
        boolean reverse,
        string  dirname)
    {
        super(reverse, dirname);
    }

    /**
     * takes an x509 dir name as a string of the format "c=au, st=victoria", or
     * some such, converting it into an ordered set of name attributes. lookup 
     * should provide a table of lookups, indexed by lowercase only strings and
     * yielding a derobjectidentifier, other than that oid. and numeric oids
     * will be processed automatically.
     * <p>
     * if reverse is true, create the encoded version of the sequence starting
     * from the last element in the string.
     */
    public x509principal(
        boolean     reverse,
        hashtable   lookup,
        string      dirname)
    {
        super(reverse, lookup, dirname);
    }

    public string getname()
    {
        return this.tostring();
    }

    /**
     * return a der encoded byte array representing this object
     */
    public byte[] getencoded()
    {
        try
        {
            return this.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new runtimeexception(e.tostring());
        }
    }
}
