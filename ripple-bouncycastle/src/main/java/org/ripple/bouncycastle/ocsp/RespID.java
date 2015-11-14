package org.ripple.bouncycastle.ocsp;

import java.security.messagedigest;
import java.security.publickey;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.ocsp.responderid;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

/**
 * carrier for a responderid.
 */
public class respid
{
    responderid id;

    public respid(
        responderid id)
    {
        this.id = id;
    }

    public respid(
        x500principal   name)
    {
        this.id = new responderid(x500name.getinstance(name.getencoded()));
    }

    public respid(
        publickey   key)
        throws ocspexception
    {
        try
        {
            // todo allow specification of a particular provider
            messagedigest digest = ocsputil.createdigestinstance("sha1", null);

            asn1inputstream ain = new asn1inputstream(key.getencoded());
            subjectpublickeyinfo info = subjectpublickeyinfo.getinstance(ain.readobject());

            digest.update(info.getpublickeydata().getbytes());

            asn1octetstring keyhash = new deroctetstring(digest.digest());

            this.id = new responderid(keyhash);
        }
        catch (exception e)
        {
            throw new ocspexception("problem creating id: " + e, e);
        }
    }

    public responderid toasn1object()
    {
        return id;
    }

    public boolean equals(
        object  o)
    {
        if (!(o instanceof respid))
        {
            return false;
        }

        respid   obj = (respid)o;

        return id.equals(obj.id);
    }

    public int hashcode()
    {
        return id.hashcode();
    }
}
