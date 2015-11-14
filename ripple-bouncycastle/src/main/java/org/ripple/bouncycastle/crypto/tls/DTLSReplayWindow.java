package org.ripple.bouncycastle.crypto.tls;

/**
 * rfc 4347 4.1.2.5 anti-replay
 * <p/>
 * support fast rejection of duplicate records by maintaining a sliding receive window
 */
class dtlsreplaywindow
{

    private static final long valid_seq_mask = 0x0000ffffffffffffl;

    private static final long window_size = 64l;

    private long latestconfirmedseq = -1;
    private long bitmap = 0;

    /**
     * check whether a received record with the given sequence number should be rejected as a duplicate.
     *
     * @param seq the 48-bit dtlsplaintext.sequence_number field of a received record.
     * @return true if the record should be discarded without further processing.
     */
    boolean shoulddiscard(long seq)
    {
        if ((seq & valid_seq_mask) != seq)
        {
            return true;
        }

        if (seq <= latestconfirmedseq)
        {
            long diff = latestconfirmedseq - seq;
            if (diff >= window_size)
            {
                return true;
            }
            if ((bitmap & (1l << diff)) != 0)
            {
                return true;
            }
        }

        return false;
    }

    /**
     * report that a received record with the given sequence number passed authentication checks.
     *
     * @param seq the 48-bit dtlsplaintext.sequence_number field of an authenticated record.
     */
    void reportauthenticated(long seq)
    {
        if ((seq & valid_seq_mask) != seq)
        {
            throw new illegalargumentexception("'seq' out of range");
        }

        if (seq <= latestconfirmedseq)
        {
            long diff = latestconfirmedseq - seq;
            if (diff < window_size)
            {
                bitmap |= (1l << diff);
            }
        }
        else
        {
            long diff = seq - latestconfirmedseq;
            if (diff >= window_size)
            {
                bitmap = 1;
            }
            else
            {
                bitmap <<= (int)diff;        // for earlier jdks
                bitmap |= 1;
            }
            latestconfirmedseq = seq;
        }
    }

    /**
     * when a new epoch begins, sequence numbers begin again at 0
     */
    void reset()
    {
        latestconfirmedseq = -1;
        bitmap = 0;
    }
}
