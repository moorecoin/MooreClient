package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * the distributionpointname object.
 * <pre>
 * distributionpointname ::= choice {
 *     fullname                 [0] generalnames,
 *     namerelativetocrlissuer  [1] rdn
 * }
 * </pre>
 */
public class distributionpointname
    extends asn1object
    implements asn1choice
{
    asn1encodable        name;
    int                 type;

    public static final int full_name = 0;
    public static final int name_relative_to_crl_issuer = 1;

    public static distributionpointname getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1taggedobject.getinstance(obj, true));
    }

    public static distributionpointname getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof distributionpointname)
        {
            return (distributionpointname)obj;
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new distributionpointname((asn1taggedobject)obj);
        }

        throw new illegalargumentexception("unknown object in factory: " + obj.getclass().getname());
    }

    public distributionpointname(
        int             type,
        asn1encodable   name)
    {
        this.type = type;
        this.name = name;
    }

    public distributionpointname(
        generalnames name)
    {
        this(full_name, name);
    }

    /**
     * return the tag number applying to the underlying choice.
     * 
     * @return the tag number for this point name.
     */
    public int gettype()
    {
        return this.type;
    }
    
    /**
     * return the tagged object inside the distribution point name.
     * 
     * @return the underlying choice item.
     */
    public asn1encodable getname()
    {
        return (asn1encodable)name;
    }
    
    public distributionpointname(
        asn1taggedobject    obj)
    {
        this.type = obj.gettagno();
        
        if (type == 0)
        {
            this.name = generalnames.getinstance(obj, false);
        }
        else
        {
            this.name = asn1set.getinstance(obj, false);
        }
    }
    
    public asn1primitive toasn1primitive()
    {
        return new dertaggedobject(false, type, name);
    }

    public string tostring()
    {
        string       sep = system.getproperty("line.separator");
        stringbuffer buf = new stringbuffer();
        buf.append("distributionpointname: [");
        buf.append(sep);
        if (type == full_name)
        {
            appendobject(buf, sep, "fullname", name.tostring());
        }
        else
        {
            appendobject(buf, sep, "namerelativetocrlissuer", name.tostring());
        }
        buf.append("]");
        buf.append(sep);
        return buf.tostring();
    }

    private void appendobject(stringbuffer buf, string sep, string name, string value)
    {
        string       indent = "    ";

        buf.append(indent);
        buf.append(name);
        buf.append(":");
        buf.append(sep);
        buf.append(indent);
        buf.append(indent);
        buf.append(value);
        buf.append(sep);
    }
}
