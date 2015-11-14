package org.ripple.bouncycastle.asn1.x509.qualified;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * the qcstatement object.
 * <pre>
 * qcstatement ::= sequence {
 *   statementid        object identifier,
 *   statementinfo      any defined by statementid optional} 
 * </pre>
 */

public class qcstatement 
    extends asn1object
    implements etsiqcobjectidentifiers, rfc3739qcobjectidentifiers
{
    asn1objectidentifier qcstatementid;
    asn1encodable        qcstatementinfo;

    public static qcstatement getinstance(
        object obj)
    {
        if (obj instanceof qcstatement)
        {
            return (qcstatement)obj;
        }
        if (obj != null)
        {
            return new qcstatement(asn1sequence.getinstance(obj));            
        }
        
        return null;
    }    
    
    private qcstatement(
        asn1sequence seq)
    {
        enumeration e = seq.getobjects();

        // qcstatementid
        qcstatementid = asn1objectidentifier.getinstance(e.nextelement());
        // qcstatementinfo
        if (e.hasmoreelements())
        {
            qcstatementinfo = (asn1encodable) e.nextelement();
        }
    }    
    
    public qcstatement(
        asn1objectidentifier qcstatementid)
    {
        this.qcstatementid = qcstatementid;
        this.qcstatementinfo = null;
    }
    
    public qcstatement(
        asn1objectidentifier qcstatementid,
        asn1encodable       qcstatementinfo)
    {
        this.qcstatementid = qcstatementid;
        this.qcstatementinfo = qcstatementinfo;
    }    
        
    public asn1objectidentifier getstatementid()
    {
        return qcstatementid;
    }
    
    public asn1encodable getstatementinfo()
    {
        return qcstatementinfo;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        seq.add(qcstatementid);       
        
        if (qcstatementinfo != null)
        {
            seq.add(qcstatementinfo);
        }

        return new dersequence(seq);
    }
}
