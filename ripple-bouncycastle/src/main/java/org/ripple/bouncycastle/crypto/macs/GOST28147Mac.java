package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithsbox;

/**
 * implementation of gost 28147-89 mac
 */
public class gost28147mac
    implements mac
{
    private int                 blocksize = 8;
    private int                 macsize = 4;
    private int                 bufoff;
    private byte[]              buf;
    private byte[]              mac;
    private boolean             firststep = true;
    private int[]               workingkey = null;

    //
    // this is default s-box - e_a.
    private byte s[] = {
            0x9,0x6,0x3,0x2,0x8,0xb,0x1,0x7,0xa,0x4,0xe,0xf,0xc,0x0,0xd,0x5,
            0x3,0x7,0xe,0x9,0x8,0xa,0xf,0x0,0x5,0x2,0x6,0xc,0xb,0x4,0xd,0x1,
            0xe,0x4,0x6,0x2,0xb,0x3,0xd,0x8,0xc,0xf,0x5,0xa,0x0,0x7,0x1,0x9,
            0xe,0x7,0xa,0xc,0xd,0x1,0x3,0x9,0x0,0x2,0xb,0x4,0xf,0x8,0x5,0x6,
            0xb,0x5,0x1,0x9,0x8,0xd,0xf,0x0,0xe,0x4,0x2,0x3,0xc,0x7,0xa,0x6,
            0x3,0xa,0xd,0xc,0x1,0x2,0x0,0xb,0x7,0x5,0x9,0x4,0x8,0xf,0xe,0x6,
            0x1,0xd,0x2,0x9,0x7,0xa,0x6,0x0,0x8,0xc,0x4,0x5,0xf,0x3,0xb,0xe,
            0xb,0xa,0xf,0x5,0x0,0xc,0xe,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xd,0x4
    };
    
    public gost28147mac()
    {
        mac = new byte[blocksize];

        buf = new byte[blocksize];
        bufoff = 0;
    }

    private int[] generateworkingkey(
        byte[]  userkey)
    {
        if (userkey.length != 32)
        {
            throw new illegalargumentexception("key length invalid. key needs to be 32 byte - 256 bit!!!");
        }

        int key[] = new int[8];
        for(int i=0; i!=8; i++)
        {
            key[i] = bytestoint(userkey,i*4);
        }

        return key;
    }
    
    public void init(
        cipherparameters params)
        throws illegalargumentexception
    {
        reset();
        buf = new byte[blocksize];
        if (params instanceof parameterswithsbox)
        {
            parameterswithsbox   param = (parameterswithsbox)params;

            //
            // set the s-box
            //
            system.arraycopy(param.getsbox(), 0, this.s, 0, param.getsbox().length);

            //
            // set key if there is one
            //
            if (param.getparameters() != null)
            {
                workingkey = generateworkingkey(((keyparameter)param.getparameters()).getkey());
            }
        }
        else if (params instanceof keyparameter)
        {
            workingkey = generateworkingkey(((keyparameter)params).getkey());
        }
        else
        {
           throw new illegalargumentexception("invalid parameter passed to gost28147 init - " + params.getclass().getname());
        }
    }

    public string getalgorithmname()
    {
        return "gost28147mac";
    }

    public int getmacsize()
    {
        return macsize;
    }

    private int gost28147_mainstep(int n1, int key)
    {
        int cm = (key + n1); // cm1
        
        // s-box replacing
        
        int om = s[  0 + ((cm >> (0 * 4)) & 0xf)] << (0 * 4);
        om += s[ 16 + ((cm >> (1 * 4)) & 0xf)] << (1 * 4);
        om += s[ 32 + ((cm >> (2 * 4)) & 0xf)] << (2 * 4);
        om += s[ 48 + ((cm >> (3 * 4)) & 0xf)] << (3 * 4);
        om += s[ 64 + ((cm >> (4 * 4)) & 0xf)] << (4 * 4);
        om += s[ 80 + ((cm >> (5 * 4)) & 0xf)] << (5 * 4);
        om += s[ 96 + ((cm >> (6 * 4)) & 0xf)] << (6 * 4);
        om += s[112 + ((cm >> (7 * 4)) & 0xf)] << (7 * 4);
        
        return om << 11 | om >>> (32-11); // 11-leftshift
    }
    
    private void gost28147macfunc(
            int[]   workingkey,
            byte[]  in,
            int     inoff,
            byte[]  out,
            int     outoff)
    {
        int n1, n2, tmp;  //tmp -> for saving n1
        n1 = bytestoint(in, inoff);
        n2 = bytestoint(in, inoff + 4);
        
        for(int k = 0; k < 2; k++)  // 1-16 steps
        {
            for(int j = 0; j < 8; j++)
            {
                tmp = n1;
                n1 = n2 ^ gost28147_mainstep(n1, workingkey[j]); // cm2
                n2 = tmp;
            }
        }
        
        inttobytes(n1, out, outoff);
        inttobytes(n2, out, outoff + 4);
    }
    
    //array of bytes to type int
    private int bytestoint(
            byte[]  in,
            int     inoff)
    {
        return  ((in[inoff + 3] << 24) & 0xff000000) + ((in[inoff + 2] << 16) & 0xff0000) +
        ((in[inoff + 1] << 8) & 0xff00) + (in[inoff] & 0xff);
    }
    
    //int to array of bytes
    private void inttobytes(
            int     num,
            byte[]  out,
            int     outoff)
    {
        out[outoff + 3] = (byte)(num >>> 24);
        out[outoff + 2] = (byte)(num >>> 16);
        out[outoff + 1] = (byte)(num >>> 8);
        out[outoff] =     (byte)num;
    }
        
    private byte[] cm5func(byte[] buf, int bufoff, byte[] mac)
    {
        byte[] sum = new byte[buf.length - bufoff];

        system.arraycopy(buf, bufoff, sum, 0, mac.length);

        for (int i = 0; i != mac.length; i++)
        {
            sum[i] = (byte)(sum[i] ^ mac[i]);
        }

        return sum;
    }

    public void update(byte in)
            throws illegalstateexception
    {
        if (bufoff == buf.length)
        {
            byte[] sumbuf = new byte[buf.length];
            system.arraycopy(buf, 0, sumbuf, 0, mac.length);

            if (firststep)
            {
                firststep = false;
            }
            else
            {
                sumbuf = cm5func(buf, 0, mac);
            }

            gost28147macfunc(workingkey, sumbuf, 0, mac, 0);
            bufoff = 0;
        }

        buf[bufoff++] = in;
    }

    public void update(byte[] in, int inoff, int len)
        throws datalengthexception, illegalstateexception
    {
            if (len < 0)
            {
                throw new illegalargumentexception("can't have a negative input length!");
            }

            int gaplen = blocksize - bufoff;

            if (len > gaplen)
            {
                system.arraycopy(in, inoff, buf, bufoff, gaplen);

                byte[] sumbuf = new byte[buf.length];
                system.arraycopy(buf, 0, sumbuf, 0, mac.length);

                if (firststep)
                {
                    firststep = false;
                }
                else
                {
                    sumbuf = cm5func(buf, 0, mac);
                }

                gost28147macfunc(workingkey, sumbuf, 0, mac, 0);

                bufoff = 0;
                len -= gaplen;
                inoff += gaplen;

                while (len > blocksize)
                {
                    sumbuf = cm5func(in, inoff, mac);
                    gost28147macfunc(workingkey, sumbuf, 0, mac, 0);

                    len -= blocksize;
                    inoff += blocksize;
                }
            }

            system.arraycopy(in, inoff, buf, bufoff, len);

            bufoff += len;    
    }     

    public int dofinal(byte[] out, int outoff)
        throws datalengthexception, illegalstateexception
    {
        //padding with zero
        while (bufoff < blocksize)
        {
            buf[bufoff] = 0;
            bufoff++;
        }

        byte[] sumbuf = new byte[buf.length];
        system.arraycopy(buf, 0, sumbuf, 0, mac.length);

        if (firststep)
        {
            firststep = false;
        }
        else
        {
            sumbuf = cm5func(buf, 0, mac);
        }

        gost28147macfunc(workingkey, sumbuf, 0, mac, 0);

        system.arraycopy(mac, (mac.length/2)-macsize, out, outoff, macsize);

        reset();

        return macsize;
    }

    public void reset()
    {
        /*
         * clean the buffer.
         */
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufoff = 0;

        firststep = true;
    }
}
