package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;

/**
 * the authoritykeyidentifier object.
 * <pre>
 * id-ce-authoritykeyidentifier object identifier ::=  { id-ce 35 }
 *
 *   authoritykeyidentifier ::= sequence {
 *      keyidentifier             [0] implicit keyidentifier           optional,
 *      authoritycertissuer       [1] implicit generalnames            optional,
 *      authoritycertserialnumber [2] implicit certificateserialnumber optional  }
 *
 *   keyidentifier ::= octet string
 * </pre>
 *
 */
public class authoritykeyidentifier
    extends asn1object
{
    asn1octetstring keyidentifier=null;
    generalnames certissuer=null;
    asn1integer certserno=null;

    public static authoritykeyidentifier getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static authoritykeyidentifier getinstance(
        object  obj)
    {
        if (obj instanceof authoritykeyidentifier)
        {
            return (authoritykeyidentifier)obj;
        }
        if (obj != null)
        {
            return new authoritykeyidentifier(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static authoritykeyidentifier fromextensions(extensions extensions)
    {
         return authoritykeyidentifier.getinstance(extensions.getextensionparsedvalue(extension.authoritykeyidentifier));
    }

    protected authoritykeyidentifier(
        asn1sequence   seq)
    {
        enumeration     e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1taggedobject o = dertaggedobject.getinstance(e.nextelement());

            switch (o.gettagno())
            {
            case 0:
                this.keyidentifier = asn1octetstring.getinstance(o, false);
                break;
            case 1:
                this.certissuer = generalnames.getinstance(o, false);
                break;
            case 2:
                this.certserno = asn1integer.getinstance(o, false);
                break;
            default:
                throw new illegalargumentexception("illegal tag");
            }
        }
    }

    /**
     *
     * calulates the keyidentifier using a sha1 hash over the bit string
     * from subjectpublickeyinfo as defined in rfc2459.
     *
     * example of making a authoritykeyidentifier:
     * <pre>
     *   subjectpublickeyinfo apki = new subjectpublickeyinfo((asn1sequence)new asn1inputstream(
     *       publickey.getencoded()).readobject());
     *   authoritykeyidentifier aki = new authoritykeyidentifier(apki);
     * </pre>
     *
     **/
    public authoritykeyidentifier(
        subjectpublickeyinfo    spki)
    {
        digest  digest = new sha1digest();
        byte[]  resbuf = new byte[digest.getdigestsize()];

        byte[] bytes = spki.getpublickeydata().getbytes();
        digest.update(bytes, 0, bytes.length);
        digest.dofinal(resbuf, 0);
        this.keyidentifier = new deroctetstring(resbuf);
    }

    /**
     * create an authoritykeyidentifier with the generalnames tag and
     * the serial number provided as well.
     */
    public authoritykeyidentifier(
        subjectpublickeyinfo    spki,
        generalnames            name,
        biginteger              serialnumber)
    {
        digest  digest = new sha1digest();
        byte[]  resbuf = new byte[digest.getdigestsize()];

        byte[] bytes = spki.getpublickeydata().getbytes();
        digest.update(bytes, 0, bytes.length);
        digest.dofinal(resbuf, 0);

        this.keyidentifier = new deroctetstring(resbuf);
        this.certissuer = generalnames.getinstance(name.toasn1primitive());
        this.certserno = new asn1integer(serialnumber);
    }

    /**
     * create an authoritykeyidentifier with the generalnames tag and
     * the serial number provided.
     */
    public authoritykeyidentifier(
        generalnames            name,
        biginteger              serialnumber)
    {
        this.keyidentifier = null;
        this.certissuer = generalnames.getinstance(name.toasn1primitive());
        this.certserno = new asn1integer(serialnumber);
    }

    /**
      * create an authoritykeyidentifier with a precomputed key identifier
      */
     public authoritykeyidentifier(
         byte[]                  keyidentifier)
     {
         this.keyidentifier = new deroctetstring(keyidentifier);
         this.certissuer = null;
         this.certserno = null;
     }

    /**
     * create an authoritykeyidentifier with a precomputed key identifier
     * and the generalnames tag and the serial number provided as well.
     */
    public authoritykeyidentifier(
        byte[]                  keyidentifier,
        generalnames            name,
        biginteger              serialnumber)
    {
        this.keyidentifier = new deroctetstring(keyidentifier);
        this.certissuer = generalnames.getinstance(name.toasn1primitive());
        this.certserno = new asn1integer(serialnumber);
    }
    
    public byte[] getkeyidentifier()
    {
        if (keyidentifier != null)
        {
            return keyidentifier.getoctets();
        }

        return null;
    }

    public generalnames getauthoritycertissuer()
    {
        return certissuer;
    }
    
    public biginteger getauthoritycertserialnumber()
    {
        if (certserno != null)
        {
            return certserno.getvalue();
        }
        
        return null;
    }
    
    /**
     * produce an object suitable for an asn1outputstream.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (keyidentifier != null)
        {
            v.add(new dertaggedobject(false, 0, keyidentifier));
        }

        if (certissuer != null)
        {
            v.add(new dertaggedobject(false, 1, certissuer));
        }

        if (certserno != null)
        {
            v.add(new dertaggedobject(false, 2, certserno));
        }


        return new dersequence(v);
    }

    public string tostring()
    {
        return ("authoritykeyidentifier: keyid(" + this.keyidentifier.getoctets() + ")");
    }
}
