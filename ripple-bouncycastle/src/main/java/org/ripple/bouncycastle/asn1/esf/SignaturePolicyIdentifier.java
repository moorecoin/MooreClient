package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1null;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.bertags;
import org.ripple.bouncycastle.asn1.dernull;

public class signaturepolicyidentifier
    extends asn1object
{
    private signaturepolicyid   signaturepolicyid;
    private boolean             issignaturepolicyimplied;

    public static signaturepolicyidentifier getinstance(
        object  obj)
    {
        if (obj instanceof signaturepolicyidentifier)
        {
            return (signaturepolicyidentifier)obj;
        }
        else if (obj instanceof asn1null || hasencodedtagvalue(obj, bertags.null))
        {
            return new signaturepolicyidentifier();
        }
        else if (obj != null)
        {
            return new signaturepolicyidentifier(signaturepolicyid.getinstance(obj));
        }

        return null;
    }

    public signaturepolicyidentifier()
    {
        this.issignaturepolicyimplied = true;
    }

    public signaturepolicyidentifier(
        signaturepolicyid signaturepolicyid)
    {
        this.signaturepolicyid = signaturepolicyid;
        this.issignaturepolicyimplied = false;
    }

    public signaturepolicyid getsignaturepolicyid()
    {
        return signaturepolicyid;
    }

    public boolean issignaturepolicyimplied()
    {
        return issignaturepolicyimplied;
    }

    /**
     * <pre>
     * signaturepolicyidentifier ::= choice{
     *     signaturepolicyid         signaturepolicyid,
     *     signaturepolicyimplied    signaturepolicyimplied }
     *
     * signaturepolicyimplied ::= null
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        if (issignaturepolicyimplied)
        {
            return dernull.instance;
        }
        else
        {
            return signaturepolicyid.toasn1primitive();
        }
    }
}
