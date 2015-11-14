package org.ripple.bouncycastle.util.io.pem;

import java.io.bufferedreader;
import java.io.ioexception;
import java.io.reader;
import java.util.arraylist;
import java.util.list;

import org.ripple.bouncycastle.util.encoders.base64;

public class pemreader
    extends bufferedreader
{
    private static final string begin = "-----begin ";
    private static final string end = "-----end ";

    public pemreader(reader reader)
    {
        super(reader);
    }

    public pemobject readpemobject()
        throws ioexception
    {
        string line = readline();

        while (line != null && !line.startswith(begin))
        {
            line = readline();
        }

        if (line != null)
        {
            line = line.substring(begin.length());
            int index = line.indexof('-');
            string type = line.substring(0, index);

            if (index > 0)
            {
                return loadobject(type);
            }
        }

        return null;
    }

    private pemobject loadobject(string type)
        throws ioexception
    {
        string          line;
        string          endmarker = end + type;
        stringbuffer    buf = new stringbuffer();
        list            headers = new arraylist();

        while ((line = readline()) != null)
        {
            if (line.indexof(":") >= 0)
            {
                int index = line.indexof(':');
                string hdr = line.substring(0, index);
                string value = line.substring(index + 1).trim();

                headers.add(new pemheader(hdr, value));

                continue;
            }

            if (line.indexof(endmarker) != -1)
            {
                break;
            }
            
            buf.append(line.trim());
        }

        if (line == null)
        {
            throw new ioexception(endmarker + " not found");
        }

        return new pemobject(type, headers, base64.decode(buf.tostring()));
    }

}
