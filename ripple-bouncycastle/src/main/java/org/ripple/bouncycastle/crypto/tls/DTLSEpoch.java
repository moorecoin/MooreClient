package org.ripple.bouncycastle.crypto.tls;

class dtlsepoch
{

    private final dtlsreplaywindow replaywindow = new dtlsreplaywindow();

    private final int epoch;
    private final tlscipher cipher;

    private long sequence_number = 0;

    dtlsepoch(int epoch, tlscipher cipher)
    {
        if (epoch < 0)
        {
            throw new illegalargumentexception("'epoch' must be >= 0");
        }
        if (cipher == null)
        {
            throw new illegalargumentexception("'cipher' cannot be null");
        }

        this.epoch = epoch;
        this.cipher = cipher;
    }

    long allocatesequencenumber()
    {
        // todo check for overflow
        return sequence_number++;
    }

    tlscipher getcipher()
    {
        return cipher;
    }

    int getepoch()
    {
        return epoch;
    }

    dtlsreplaywindow getreplaywindow()
    {
        return replaywindow;
    }

    long getsequence_number()
    {
        return sequence_number;
    }
}
