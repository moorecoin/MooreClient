package org.ripple.bouncycastle.crypto.tls;

import java.util.vector;

class dtlsreassembler
{

    private final short msg_type;
    private final byte[] body;

    private vector missing = new vector();

    dtlsreassembler(short msg_type, int length)
    {
        this.msg_type = msg_type;
        this.body = new byte[length];
        this.missing.addelement(new range(0, length));
    }

    short gettype()
    {
        return msg_type;
    }

    byte[] getbodyifcomplete()
    {
        return missing.isempty() ? body : null;
    }

    void contributefragment(short msg_type, int length, byte[] buf, int off, int fragment_offset,
                            int fragment_length)
    {

        int fragment_end = fragment_offset + fragment_length;

        if (this.msg_type != msg_type || this.body.length != length || fragment_end > length)
        {
            return;
        }

        if (fragment_length == 0)
        {
            // note: empty messages still require an empty fragment to complete it
            if (fragment_offset == 0 && !missing.isempty())
            {
                range firstrange = (range)missing.firstelement();
                if (firstrange.getend() == 0)
                {
                    missing.removeelementat(0);
                }
            }
            return;
        }

        for (int i = 0; i < missing.size(); ++i)
        {
            range range = (range)missing.elementat(i);
            if (range.getstart() >= fragment_end)
            {
                break;
            }
            if (range.getend() > fragment_offset)
            {

                int copystart = math.max(range.getstart(), fragment_offset);
                int copyend = math.min(range.getend(), fragment_end);
                int copylength = copyend - copystart;

                system.arraycopy(buf, off + copystart - fragment_offset, body, copystart,
                    copylength);

                if (copystart == range.getstart())
                {
                    if (copyend == range.getend())
                    {
                        missing.removeelementat(i--);
                    }
                    else
                    {
                        range.setstart(copyend);
                    }
                }
                else
                {
                    if (copyend == range.getend())
                    {
                        range.setend(copystart);
                    }
                    else
                    {
                        missing.insertelementat(new range(copyend, range.getend()), ++i);
                        range.setend(copystart);
                    }
                }
            }
        }
    }

    void reset()
    {
        this.missing.removeallelements();
        this.missing.addelement(new range(0, body.length));
    }

    private static class range
    {

        private int start, end;

        range(int start, int end)
        {
            this.start = start;
            this.end = end;
        }

        public int getstart()
        {
            return start;
        }

        public void setstart(int start)
        {
            this.start = start;
        }

        public int getend()
        {
            return end;
        }

        public void setend(int end)
        {
            this.end = end;
        }
    }
}
