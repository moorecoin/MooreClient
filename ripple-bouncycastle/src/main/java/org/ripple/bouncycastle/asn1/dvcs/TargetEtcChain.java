package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * <pre>
 *     targetetcchain ::= sequence {
 *         target                       certetctoken,
 *         chain                        sequence size (1..max) of
 *                                         certetctoken optional,
 *         pathprocinput                [0] pathprocinput optional
 *     }
 * </pre>
 */

public class targetetcchain
    extends asn1object
{
    private certetctoken target;
    private asn1sequence chain;
    private pathprocinput pathprocinput;

    public targetetcchain(certetctoken target)
    {
        this(target, null, null);
    }

    public targetetcchain(certetctoken target, certetctoken[] chain)
    {
        this(target, chain, null);
    }

    public targetetcchain(certetctoken target, pathprocinput pathprocinput)
    {
        this(target, null, pathprocinput);
    }

    public targetetcchain(certetctoken target, certetctoken[] chain, pathprocinput pathprocinput)
    {
        this.target = target;

        if (chain != null)
        {
            this.chain = new dersequence(chain);
        }

        this.pathprocinput = pathprocinput;
    }

    private targetetcchain(asn1sequence seq)
    {
        int i = 0;
        asn1encodable obj = seq.getobjectat(i++);
        this.target = certetctoken.getinstance(obj);

        try
        {
            obj = seq.getobjectat(i++);
            this.chain = asn1sequence.getinstance(obj);
        }
        catch (illegalargumentexception e)
        {
        }
        catch (indexoutofboundsexception e)
        {
            return;
        }

        try
        {
            obj = seq.getobjectat(i++);
            asn1taggedobject tagged = asn1taggedobject.getinstance(obj);
            switch (tagged.gettagno())
            {
            case 0:
                this.pathprocinput = pathprocinput.getinstance(tagged, false);
                break;
            }
        }
        catch (illegalargumentexception e)
        {
        }
        catch (indexoutofboundsexception e)
        {
        }
    }

    public static targetetcchain getinstance(object obj)
    {
        if (obj instanceof targetetcchain)
        {
            return (targetetcchain)obj;
        }
        else if (obj != null)
        {
            return new targetetcchain(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static targetetcchain getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(target);
        if (chain != null)
        {
            v.add(chain);
        }
        if (pathprocinput != null)
        {
            v.add(new dertaggedobject(false, 0, pathprocinput));
        }

        return new dersequence(v);
    }

    public string tostring()
    {
        stringbuffer s = new stringbuffer();
        s.append("targetetcchain {\n");
        s.append("target: " + target + "\n");
        if (chain != null)
        {
            s.append("chain: " + chain + "\n");
        }
        if (pathprocinput != null)
        {
            s.append("pathprocinput: " + pathprocinput + "\n");
        }
        s.append("}\n");
        return s.tostring();
    }


    public certetctoken gettarget()
    {
        return target;
    }

    public certetctoken[] getchain()
    {
        if (chain != null)
        {
            return certetctoken.arrayfromsequence(chain);
        }

        return null;
    }

    private void setchain(asn1sequence chain)
    {
        this.chain = chain;
    }

    public pathprocinput getpathprocinput()
    {
        return pathprocinput;
    }

    private void setpathprocinput(pathprocinput pathprocinput)
    {
        this.pathprocinput = pathprocinput;
    }

    public static targetetcchain[] arrayfromsequence(asn1sequence seq)
    {
        targetetcchain[] tmp = new targetetcchain[seq.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = targetetcchain.getinstance(seq.getobjectat(i));
        }

        return tmp;
    }
}
