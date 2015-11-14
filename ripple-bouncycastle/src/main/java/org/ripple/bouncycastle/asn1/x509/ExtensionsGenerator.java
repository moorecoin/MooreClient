package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.deroctetstring;

/**
 * generator for x.509 extensions
 */
public class extensionsgenerator
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
     * add an extension with the given oid and the passed in value to be included
     * in the octet string associated with the extension.
     *
     * @param oid  oid for the extension.
     * @param critical  true if critical, false otherwise.
     * @param value the asn.1 object to be included in the extension.
     */
    public void addextension(
        asn1objectidentifier oid,
        boolean              critical,
        asn1encodable        value)
        throws ioexception
    {
        this.addextension(oid, critical, value.toasn1primitive().getencoded(asn1encoding.der));
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
        extensions.put(oid, new extension(oid, critical, new deroctetstring(value)));
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
     * generate an extensions object based on the current state of the generator.
     *
     * @return  an x09extensions object.
     */
    public extensions generate()
    {
        extension[] exts = new extension[extordering.size()];

        for (int i = 0; i != extordering.size(); i++)
        {
            exts[i] = (extension)extensions.get(extordering.elementat(i));
        }

        return new extensions(exts);
    }
}
