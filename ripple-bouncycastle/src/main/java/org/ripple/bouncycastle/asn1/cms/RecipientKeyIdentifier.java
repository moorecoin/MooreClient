package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class recipientkeyidentifier
    extends asn1object
{
    private asn1octetstring      subjectkeyidentifier;
    private dergeneralizedtime   date;
    private otherkeyattribute    other;

    public recipientkeyidentifier(
        asn1octetstring         subjectkeyidentifier,
        dergeneralizedtime      date,
        otherkeyattribute       other)
    {
        this.subjectkeyidentifier = subjectkeyidentifier;
        this.date = date;
        this.other = other;
    }

    public recipientkeyidentifier(
        byte[]                  subjectkeyidentifier,
        dergeneralizedtime      date,
        otherkeyattribute       other)
    {
        this.subjectkeyidentifier = new deroctetstring(subjectkeyidentifier);
        this.date = date;
        this.other = other;
    }

    public recipientkeyidentifier(
        byte[]         subjectkeyidentifier)
    {
        this(subjectkeyidentifier, null, null);
    }

    public recipientkeyidentifier(
        asn1sequence seq)
    {
        subjectkeyidentifier = asn1octetstring.getinstance(
                                                    seq.getobjectat(0));
        
        switch(seq.size())
        {
        case 1:
            break;
        case 2:
            if (seq.getobjectat(1) instanceof dergeneralizedtime)
            {
                date = (dergeneralizedtime)seq.getobjectat(1); 
            }
            else
            {
                other = otherkeyattribute.getinstance(seq.getobjectat(2));
            }
            break;
        case 3:
            date  = (dergeneralizedtime)seq.getobjectat(1);
            other = otherkeyattribute.getinstance(seq.getobjectat(2));
            break;
        default:
            throw new illegalargumentexception("invalid recipientkeyidentifier");
        }
    }

    /**
     * return a recipientkeyidentifier object from a tagged object.
     *
     * @param _ato the tagged object holding the object we want.
     * @param _explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static recipientkeyidentifier getinstance(asn1taggedobject _ato, boolean _explicit)
    {
        return getinstance(asn1sequence.getinstance(_ato, _explicit));
    }
    
    /**
     * return a recipientkeyidentifier object from the given object.
     *
     * @param _obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static recipientkeyidentifier getinstance(object _obj)
    {
        if(_obj == null || _obj instanceof recipientkeyidentifier)
        {
            return (recipientkeyidentifier)_obj;
        }
        
        if(_obj instanceof asn1sequence)
        {
            return new recipientkeyidentifier((asn1sequence)_obj);
        }
        
        throw new illegalargumentexception("invalid recipientkeyidentifier: " + _obj.getclass().getname());
    } 

    public asn1octetstring getsubjectkeyidentifier()
    {
        return subjectkeyidentifier;
    }

    public dergeneralizedtime getdate()
    {
        return date;
    }

    public otherkeyattribute getotherkeyattribute()
    {
        return other;
    }


    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * recipientkeyidentifier ::= sequence {
     *     subjectkeyidentifier subjectkeyidentifier,
     *     date generalizedtime optional,
     *     other otherkeyattribute optional 
     * }
     *
     * subjectkeyidentifier ::= octet string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(subjectkeyidentifier);
        
        if (date != null)
        {
            v.add(date);
        }

        if (other != null)
        {
            v.add(other);
        }
        
        return new dersequence(v);
    }
}
