package org.ripple.bouncycastle.asn1.x500.style;

/**
 * class for breaking up an x500 name into it's component tokens, ala
 * java.util.stringtokenizer. we need this class as some of the
 * lightweight java environment don't support classes like
 * stringtokenizer.
 */
class x500nametokenizer
{
    private string          value;
    private int             index;
    private char            separator;
    private stringbuffer    buf = new stringbuffer();

    public x500nametokenizer(
        string  oid)
    {
        this(oid, ',');
    }
    
    public x500nametokenizer(
        string  oid,
        char    separator)
    {
        this.value = oid;
        this.index = -1;
        this.separator = separator;
    }

    public boolean hasmoretokens()
    {
        return (index != value.length());
    }

    public string nexttoken()
    {
        if (index == value.length())
        {
            return null;
        }

        int     end = index + 1;
        boolean quoted = false;
        boolean escaped = false;

        buf.setlength(0);

        while (end != value.length())
        {
            char    c = value.charat(end);

            if (c == '"')
            {
                if (!escaped)
                {
                    quoted = !quoted;
                }
                buf.append(c);
                escaped = false;
            }
            else
            {
                if (escaped || quoted)
                {
                    buf.append(c);
                    escaped = false;
                }
                else if (c == '\\')
                {
                    buf.append(c);
                    escaped = true;
                }
                else if (c == separator)
                {
                    break;
                }
                else
                {
                    buf.append(c);
                }
            }
            end++;
        }

        index = end;

        return buf.tostring();
    }
}
