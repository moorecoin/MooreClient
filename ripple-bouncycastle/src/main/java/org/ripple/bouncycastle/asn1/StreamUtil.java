package org.ripple.bouncycastle.asn1;

import java.io.bytearrayinputstream;
import java.io.fileinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.nio.channels.filechannel;

class streamutil
{
    private static final long  max_memory = runtime.getruntime().maxmemory();

    /**
     * find out possible longest length...
     *
     * @param in input stream of interest
     * @return length calculation or max_value.
     */
    static int findlimit(inputstream in)
    {
        if (in instanceof limitedinputstream)
        {
            return ((limitedinputstream)in).getremaining();
        }
        else if (in instanceof asn1inputstream)
        {
            return ((asn1inputstream)in).getlimit();
        }
        else if (in instanceof bytearrayinputstream)
        {
            return ((bytearrayinputstream)in).available();
        }
        else if (in instanceof fileinputstream)
        {
            try
            {
                filechannel channel = ((fileinputstream)in).getchannel();
                long  size = (channel != null) ? channel.size() : integer.max_value;

                if (size < integer.max_value)
                {
                    return (int)size;
                }
            }
            catch (ioexception e)
            {
                // ignore - they'll find out soon enough!
            }
        }

        if (max_memory > integer.max_value)
        {
            return integer.max_value;
        }

        return (int)max_memory;
    }

    static int calculatebodylength(
        int length)
    {
        int count = 1;

        if (length > 127)
        {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0)
            {
                size++;
            }

            for (int i = (size - 1) * 8; i >= 0; i -= 8)
            {
                count++;
            }
        }

        return count;
    }

    static int calculatetaglength(int tagno)
        throws ioexception
    {
        int length = 1;

        if (tagno >= 31)
        {
            if (tagno < 128)
            {
                length++;
            }
            else
            {
                byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tagno & 0x7f);

                do
                {
                    tagno >>= 7;
                    stack[--pos] = (byte)(tagno & 0x7f | 0x80);
                }
                while (tagno > 127);

                length += stack.length - pos;
            }
        }

        return length;
    }
}
