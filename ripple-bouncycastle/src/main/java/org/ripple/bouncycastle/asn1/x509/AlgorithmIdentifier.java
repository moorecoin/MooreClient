package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;

public class algorithmidentifier
    extends asn1object
{
    private asn1objectidentifier objectid;
    private asn1encodable       parameters;
    private boolean             parametersdefined = false;

    public static algorithmidentifier getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    public static algorithmidentifier getinstance(
        object  obj)
    {
        if (obj== null || obj instanceof algorithmidentifier)
        {
            return (algorithmidentifier)obj;
        }

        // todo: delete
        if (obj instanceof asn1objectidentifier)
        {
            return new algorithmidentifier((asn1objectidentifier)obj);
        }

        // todo: delete
        if (obj instanceof string)
        {
            return new algorithmidentifier((string)obj);
        }

        return new algorithmidentifier(asn1sequence.getinstance(obj));
    }

    public algorithmidentifier(
        asn1objectidentifier     objectid)
    {
        this.objectid = objectid;
    }

    /**
     * @deprecated use asn1objectidentifier
     * @param objectid
     */
    public algorithmidentifier(
        string     objectid)
    {
        this.objectid = new asn1objectidentifier(objectid);
    }

    /**
     * @deprecated use asn1objectidentifier
     * @param objectid
     */
    public algorithmidentifier(
        derobjectidentifier    objectid)
    {
        this.objectid = new asn1objectidentifier(objectid.getid());
    }

    /**
     * @deprecated use asn1objectidentifier
     * @param objectid
     * @param parameters
     */
    public algorithmidentifier(
        derobjectidentifier objectid,
        asn1encodable           parameters)
    {
        parametersdefined = true;
        this.objectid = new asn1objectidentifier(objectid.getid());
        this.parameters = parameters;
    }

    public algorithmidentifier(
        asn1objectidentifier     objectid,
        asn1encodable           parameters)
    {
        parametersdefined = true;
        this.objectid = objectid;
        this.parameters = parameters;
    }

    /**
     * @deprecated use algorithmidentifier.getinstance()
     * @param seq
     */
    public algorithmidentifier(
        asn1sequence   seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }
        
        objectid = asn1objectidentifier.getinstance(seq.getobjectat(0));

        if (seq.size() == 2)
        {
            parametersdefined = true;
            parameters = seq.getobjectat(1);
        }
        else
        {
            parameters = null;
        }
    }

    public asn1objectidentifier getalgorithm()
    {
        return new asn1objectidentifier(objectid.getid());
    }

    /**
     * @deprecated use getalgorithm
     * @return
     */
    public asn1objectidentifier getobjectid()
    {
        return objectid;
    }

    public asn1encodable getparameters()
    {
        return parameters;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *      algorithmidentifier ::= sequence {
     *                            algorithm object identifier,
     *                            parameters any defined by algorithm optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(objectid);

        if (parametersdefined)
        {
            if (parameters != null)
            {
                v.add(parameters);
            }
            else
            {
                v.add(dernull.instance);
            }
        }

        return new dersequence(v);
    }
}
