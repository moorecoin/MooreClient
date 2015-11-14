package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.ioexception;
import java.io.outputstream;
import java.security.generalsecurityexception;
import java.security.messagedigest;
import java.security.provider;

import org.ripple.bouncycastle.jcajce.defaultjcajcehelper;
import org.ripple.bouncycastle.jcajce.namedjcajcehelper;
import org.ripple.bouncycastle.jcajce.providerjcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculatorprovider;

public class jcapgpdigestcalculatorproviderbuilder
{
    private operatorhelper helper = new operatorhelper(new defaultjcajcehelper());

    public jcapgpdigestcalculatorproviderbuilder()
    {
    }

    public jcapgpdigestcalculatorproviderbuilder setprovider(provider provider)
    {
        this.helper = new operatorhelper(new providerjcajcehelper(provider));

        return this;
    }

    public jcapgpdigestcalculatorproviderbuilder setprovider(string providername)
    {
        this.helper = new operatorhelper(new namedjcajcehelper(providername));

        return this;
    }

    public pgpdigestcalculatorprovider build()
        throws pgpexception
    {
        return new pgpdigestcalculatorprovider()
        {
            public pgpdigestcalculator get(final int algorithm)
                throws pgpexception
            {
                final digestoutputstream stream;
                final messagedigest dig;

                try
                {
                    dig = helper.createdigest(algorithm);

                    stream = new digestoutputstream(dig);
                }
                catch (generalsecurityexception e)
                {
                    throw new pgpexception("exception on setup: " + e, e);
                }

                return new pgpdigestcalculator()
                {
                    public int getalgorithm()
                    {
                        return algorithm;
                    }

                    public outputstream getoutputstream()
                    {
                        return stream;
                    }

                    public byte[] getdigest()
                    {
                        return stream.getdigest();
                    }

                    public void reset()
                    {
                        dig.reset();
                    }
                };
            }
        };
    }

    private class digestoutputstream
        extends outputstream
    {
        private messagedigest dig;

        digestoutputstream(messagedigest dig)
        {
            this.dig = dig;
        }

        public void write(byte[] bytes, int off, int len)
            throws ioexception
        {
            dig.update(bytes, off, len);
        }

        public void write(byte[] bytes)
            throws ioexception
        {
           dig.update(bytes);
        }

        public void write(int b)
            throws ioexception
        {
           dig.update((byte)b);
        }

        byte[] getdigest()
        {
            return dig.digest();
        }
    }
}
