package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public class dtlstransport
    implements datagramtransport
{

    private final dtlsrecordlayer recordlayer;

    dtlstransport(dtlsrecordlayer recordlayer)
    {
        this.recordlayer = recordlayer;
    }

    public int getreceivelimit()
        throws ioexception
    {
        return recordlayer.getreceivelimit();
    }

    public int getsendlimit()
        throws ioexception
    {
        return recordlayer.getsendlimit();
    }

    public int receive(byte[] buf, int off, int len, int waitmillis)
        throws ioexception
    {
        try
        {
            return recordlayer.receive(buf, off, len, waitmillis);
        }
        catch (tlsfatalalert fatalalert)
        {
            recordlayer.fail(fatalalert.getalertdescription());
            throw fatalalert;
        }
        catch (ioexception e)
        {
            recordlayer.fail(alertdescription.internal_error);
            throw e;
        }
        catch (runtimeexception e)
        {
            recordlayer.fail(alertdescription.internal_error);
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public void send(byte[] buf, int off, int len)
        throws ioexception
    {
        try
        {
            recordlayer.send(buf, off, len);
        }
        catch (tlsfatalalert fatalalert)
        {
            recordlayer.fail(fatalalert.getalertdescription());
            throw fatalalert;
        }
        catch (ioexception e)
        {
            recordlayer.fail(alertdescription.internal_error);
            throw e;
        }
        catch (runtimeexception e)
        {
            recordlayer.fail(alertdescription.internal_error);
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public void close()
        throws ioexception
    {
        recordlayer.close();
    }
}
