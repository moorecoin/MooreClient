package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.deroctetstring;

/**
 * generator for x.509 extensions
 * @deprecated use org.bouncycastle.asn1.x509.extensionsgenerator
 */
public class x509extensionsgenerator
{
    private hashtable extensions = new hashtable();
    private vector extordering = new vector();

    /**
     * reset the generator
     */
    public void reset()
    {
        extensions = new hashtable();
        extordering = new vector();
    }

    /**
     * @deprecated use asn1objectidentifier
     */
    public void addextension(
        derobjectidentifier oid,
        boolean             critical,
        asn1encodable       value)
    {
        addextension(new asn1objectidentifier(oid.getid()), critical, value);
    }

    /**
     * @deprecated use asn1objectidentifier
     */
    public void addextension(
        derobjectidentifier oid,
        boolean             critical,
        byte[]              value)
    {
        addextension(new asn1objectidentifier(oid.getid()), critical, value);
    }

    /**
     * add an extension with the given oid and the passed in value to be included
     * in the octet string associated with the extension.
     *
     * @param oid  oid for the extension.
     * @param critical  true if critical, false otherwise.
     * @param value the asn.1 object to be included in the extension.
     */
    public void addextension(
        asn1objectidentifier oid,
        boolean             critical,
        asn1encodable       value)
    {
        try
        {
            this.addextension(oid, critical, value.toasn1primitive().getencoded(asn1encoding.der));
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("error encoding value: " + e);
        }
    }

    /**
     * add an extension with the given oid and the passed in byte array to be wrapped in the
     * octet string associated with the extension.
     *
     * @param oid oid for the extension.
     * @param critical true if critical, false otherwise.
     * @param value the byte array to be wrapped.
     */
    public void addextension(
        asn1objectidentifier oid,
        boolean             critical,
        byte[]              value)
    {
        if (extensions.containskey(oid))
        {
            throw new illegalargumentexception("extension " + oid + " already added");
        }

        extordering.addelement(oid);
        extensions.put(oid, new x509extension(critical, new deroctetstring(value)));
    }

    /**
     * return true if there are no extension present in this generator.
     *
     * @return true if empty, false otherwise
     */
    public boolean isempty()
    {
        return extordering.isempty();
    }

    /**
     * generate an x509extensions object based on the current state of the generator.
     *
     * @return  an x09extensions object.
     */
    public x509extensions generate()
    {
        return new x509extensions(extordering, extensions);
    }
}
