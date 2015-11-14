package org.ripple.bouncycastle.util.io.pem;

import java.util.arraylist;
import java.util.collections;
import java.util.list;

public class pemobject
    implements pemobjectgenerator
{
    private static final list empty_list = collections.unmodifiablelist(new arraylist());

    private string type;
    private list   headers;
    private byte[] content;

    /**
     * generic constructor for object without headers.
     *
     * @param type pem object type.
     * @param content the binary content of the object.
     */
    public pemobject(string type, byte[] content)
    {
        this(type, empty_list, content);
    }

    /**
     * generic constructor for object with headers.
     *
     * @param type pem object type.
     * @param headers a list of pemheader objects.
     * @param content the binary content of the object.
     */
    public pemobject(string type, list headers, byte[] content)
    {
        this.type = type;
        this.headers = collections.unmodifiablelist(headers);
        this.content = content;
    }

    public string gettype()
    {
        return type;
    }

    public list getheaders()
    {
        return headers;
    }

    public byte[] getcontent()
    {
        return content;
    }

    public pemobject generate()
        throws pemgenerationexception
    {
        return this;
    }
}
