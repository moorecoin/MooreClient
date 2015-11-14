package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.bertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * the encrypteddata object.
 * <pre>
 *      encrypteddata ::= sequence {
 *           version version,
 *           encryptedcontentinfo encryptedcontentinfo
 *      }
 *
 *
 *      encryptedcontentinfo ::= sequence {
 *          contenttype contenttype,
 *          contentencryptionalgorithm  contentencryptionalgorithmidentifier,
 *          encryptedcontent [0] implicit encryptedcontent optional
 *    }
 *
 *    encryptedcontent ::= octet string
 * </pre>
 */
public class encrypteddata
    extends asn1object
{
    asn1sequence                data;
    asn1objectidentifier bagid;
    asn1primitive bagvalue;

    public static encrypteddata getinstance(
         object  obj)
    {
         if (obj instanceof encrypteddata)
         {
             return (encrypteddata)obj;
         }

         if (obj != null)
         {
             return new encrypteddata(asn1sequence.getinstance(obj));
         }

         return null;
    }
     
    private encrypteddata(
        asn1sequence seq)
    {
        int version = ((asn1integer)seq.getobjectat(0)).getvalue().intvalue();

        if (version != 0)
        {
            throw new illegalargumentexception("sequence not version 0");
        }

        this.data = asn1sequence.getinstance(seq.getobjectat(1));
    }

    public encrypteddata(
        asn1objectidentifier contenttype,
        algorithmidentifier     encryptionalgorithm,
        asn1encodable content)
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(contenttype);
        v.add(encryptionalgorithm.toasn1primitive());
        v.add(new bertaggedobject(false, 0, content));

        data = new bersequence(v);
    }
        
    public asn1objectidentifier getcontenttype()
    {
        return asn1objectidentifier.getinstance(data.getobjectat(0));
    }

    public algorithmidentifier getencryptionalgorithm()
    {
        return algorithmidentifier.getinstance(data.getobjectat(1));
    }

    public asn1octetstring getcontent()
    {
        if (data.size() == 3)
        {
            asn1taggedobject o = asn1taggedobject.getinstance(data.getobjectat(2));

            return asn1octetstring.getinstance(o, false);
        }

        return null;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(0));
        v.add(data);

        return new bersequence(v);
    }
}
