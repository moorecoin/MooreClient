package org.ripple.bouncycastle.asn1;

/**
 * class for breaking up an oid into it's component tokens, ala
 * java.util.stringtokenizer. we need this class as some of the
 * lightweight java environment don't support classes like
 * stringtokenizer.
 */
public class oidtokenizer
{
    private string  oid;
    private int     index;

    public oidtokenizer(
        string oid)
    {
        this.oid = oid;
        this.index = 0;
    }

    public boolean hasmoretokens()
    {
        return (index != -1);
    }

    public string nexttoken()
    {
        if (index == -1)
        {
            return null;
        }

        string  token;
        int     end = oid.indexof('.', index);

        if (end == -1)
        {
            token = oid.substring(index);
            index = -1;
            return token;
        }

        token = oid.substring(index, end);

        index = end + 1;
        return token;
    }
}
