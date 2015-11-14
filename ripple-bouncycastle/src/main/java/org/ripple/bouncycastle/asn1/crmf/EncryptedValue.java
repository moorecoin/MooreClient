package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class encryptedvalue
    extends asn1object
{
    private algorithmidentifier intendedalg;
    private algorithmidentifier symmalg;
    private derbitstring        encsymmkey;
    private algorithmidentifier keyalg;
    private asn1octetstring     valuehint;
    private derbitstring        encvalue;

    private encryptedvalue(asn1sequence seq)
    {
        int index = 0;
        while (seq.getobjectat(index) instanceof asn1taggedobject)
        {
            asn1taggedobject tobj = (asn1taggedobject)seq.getobjectat(index);

            switch (tobj.gettagno())
            {
            case 0:
                intendedalg = algorithmidentifier.getinstance(tobj, false);
                break;
            case 1:
                symmalg = algorithmidentifier.getinstance(tobj, false);
                break;
            case 2:
                encsymmkey = derbitstring.getinstance(tobj, false);
                break;
            case 3:
                keyalg = algorithmidentifier.getinstance(tobj, false);
                break;
            case 4:
                valuehint = asn1octetstring.getinstance(tobj, false);
                break;
            }
            index++;
        }

        encvalue = derbitstring.getinstance(seq.getobjectat(index));
    }

    public static encryptedvalue getinstance(object o)
    {
        if (o instanceof encryptedvalue)
        {
            return (encryptedvalue)o;
        }
        else if (o != null)
        {
            return new encryptedvalue(asn1sequence.getinstance(o));
        }

        return null;
    }

    public encryptedvalue(
        algorithmidentifier intendedalg,
        algorithmidentifier symmalg,
        derbitstring encsymmkey,
        algorithmidentifier keyalg,
        asn1octetstring valuehint,
        derbitstring encvalue)
    {
        if (encvalue == null)
        {
            throw new illegalargumentexception("'encvalue' cannot be null");
        }

        this.intendedalg = intendedalg;
        this.symmalg = symmalg;
        this.encsymmkey = encsymmkey;
        this.keyalg = keyalg;
        this.valuehint = valuehint;
        this.encvalue = encvalue;
    }

    public algorithmidentifier getintendedalg()
    {
        return intendedalg;
    }

    public algorithmidentifier getsymmalg()
    {
        return symmalg;
    }

    public derbitstring getencsymmkey()
    {
        return encsymmkey;
    }

    public algorithmidentifier getkeyalg()
    {
        return keyalg;
    }

    public asn1octetstring getvaluehint()
    {
        return valuehint;
    }

    public derbitstring getencvalue()
    {
        return encvalue;
    }

    /**
     * <pre>
     * encryptedvalue ::= sequence {
     *                     intendedalg   [0] algorithmidentifier  optional,
     *                     -- the intended algorithm for which the value will be used
     *                     symmalg       [1] algorithmidentifier  optional,
     *                     -- the symmetric algorithm used to encrypt the value
     *                     encsymmkey    [2] bit string           optional,
     *                     -- the (encrypted) symmetric key used to encrypt the value
     *                     keyalg        [3] algorithmidentifier  optional,
     *                     -- algorithm used to encrypt the symmetric key
     *                     valuehint     [4] octet string         optional,
     *                     -- a brief description or identifier of the encvalue content
     *                     -- (may be meaningful only to the sending entity, and used only
     *                     -- if encryptedvalue might be re-examined by the sending entity
     *                     -- in the future)
     *                     encvalue       bit string }
     *                     -- the encrypted value itself
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        addoptional(v, 0, intendedalg);
        addoptional(v, 1, symmalg);
        addoptional(v, 2, encsymmkey);
        addoptional(v, 3, keyalg);
        addoptional(v, 4, valuehint);

        v.add(encvalue);

        return new dersequence(v);
    }

    private void addoptional(asn1encodablevector v, int tagno, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(new dertaggedobject(false, tagno, obj));
        }
    }
}
