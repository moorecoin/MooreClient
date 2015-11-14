package org.ripple.bouncycastle.asn1;

public class asn1objectidentifier
    extends derobjectidentifier
{
    public asn1objectidentifier(string identifier)
    {
        super(identifier);
    }

    asn1objectidentifier(byte[] bytes)
    {
        super(bytes);
    }

    asn1objectidentifier(asn1objectidentifier oid, string branch)
    {
        super(oid, branch);
    }

    /**
     * return an oid that creates a branch under the current one.
     *
     * @param branchid node numbers for the new branch.
     * @return the oid for the new created branch.
     */
    public asn1objectidentifier branch(string branchid)
    {
        return new asn1objectidentifier(this, branchid);
    }

    /**
     * return  true if this oid is an extension of the passed in branch, stem.
     * @param stem the arc or branch that is a possible parent.
     * @return  true if the branch is on the passed in stem, false otherwise.
     */
    public boolean on(asn1objectidentifier stem)
    {
        string id = getid(), stemid = stem.getid();
        return id.length() > stemid.length() && id.charat(stemid.length()) == '.' && id.startswith(stemid);
    }
}
