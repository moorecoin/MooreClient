package org.ripple.bouncycastle.crypto.agreement.jpake;

import java.math.biginteger;

/**
 * the payload sent/received during the optional third round of a j-pake exchange,
 * which is for explicit key confirmation.
 * <p/>
 * <p/>
 * each {@link jpakeparticipant} creates and sends an instance
 * of this payload to the other {@link jpakeparticipant}.
 * the payload to send should be created via
 * {@link jpakeparticipant#createround3payloadtosend(biginteger)}
 * <p/>
 * <p/>
 * each {@link jpakeparticipant} must also validate the payload
 * received from the other {@link jpakeparticipant}.
 * the received payload should be validated via
 * {@link jpakeparticipant#validateround3payloadreceived(jpakeround3payload, biginteger)}
 * <p/>
 */
public class jpakeround3payload
{
    /**
     * the id of the {@link jpakeparticipant} who created/sent this payload.
     */
    private final string participantid;

    /**
     * the value of mactag, as computed by round 3.
     *
     * @see jpakeutil#calculatemactag(string, string, biginteger, biginteger, biginteger, biginteger, biginteger, org.bouncycastle.crypto.digest)
     */
    private final biginteger mactag;

    public jpakeround3payload(string participantid, biginteger magtag)
    {
        this.participantid = participantid;
        this.mactag = magtag;
    }

    public string getparticipantid()
    {
        return participantid;
    }

    public biginteger getmactag()
    {
        return mactag;
    }

}
