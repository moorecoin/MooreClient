package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.objectinputstream;
import java.io.objectoutputstream;
import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1outputstream;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;

public class pkcs12bagattributecarrierimpl
    implements pkcs12bagattributecarrier
{
    private hashtable pkcs12attributes;
    private vector pkcs12ordering;

    pkcs12bagattributecarrierimpl(hashtable attributes, vector ordering)
    {
        this.pkcs12attributes = attributes;
        this.pkcs12ordering = ordering;
    }

    public pkcs12bagattributecarrierimpl()
    {
        this(new hashtable(), new vector());
    }

    public void setbagattribute(
        asn1objectidentifier oid,
        asn1encodable        attribute)
    {
        if (pkcs12attributes.containskey(oid))
        {                           // preserve original ordering
            pkcs12attributes.put(oid, attribute);
        }
        else
        {
            pkcs12attributes.put(oid, attribute);
            pkcs12ordering.addelement(oid);
        }
    }

    public asn1encodable getbagattribute(
        asn1objectidentifier oid)
    {
        return (asn1encodable)pkcs12attributes.get(oid);
    }

    public enumeration getbagattributekeys()
    {
        return pkcs12ordering.elements();
    }

    int size()
    {
        return pkcs12ordering.size();
    }

    hashtable getattributes()
    {
        return pkcs12attributes;
    }

    vector getordering()
    {
        return pkcs12ordering;
    }

    public void writeobject(objectoutputstream out)
        throws ioexception
    {
        if (pkcs12ordering.size() == 0)
        {
            out.writeobject(new hashtable());
            out.writeobject(new vector());
        }
        else
        {
            bytearrayoutputstream bout = new bytearrayoutputstream();
            asn1outputstream aout = new asn1outputstream(bout);

            enumeration             e = this.getbagattributekeys();

            while (e.hasmoreelements())
            {
                derobjectidentifier    oid = (derobjectidentifier)e.nextelement();

                aout.writeobject(oid);
                aout.writeobject((asn1encodable)pkcs12attributes.get(oid));
            }

            out.writeobject(bout.tobytearray());
        }
    }

    public void readobject(objectinputstream in)
        throws ioexception, classnotfoundexception
    {
        object obj = in.readobject();

        if (obj instanceof hashtable)
        {
            this.pkcs12attributes = (hashtable)obj;
            this.pkcs12ordering = (vector)in.readobject();
        }
        else
        {
            asn1inputstream ain = new asn1inputstream((byte[])obj);

            asn1objectidentifier    oid;

            while ((oid = (asn1objectidentifier)ain.readobject()) != null)
            {
                this.setbagattribute(oid, ain.readobject());
            }
        }
    }
}
