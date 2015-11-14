package org.ripple.bouncycastle.crypto.agreement.jpake;

import java.math.biginteger;

import org.ripple.bouncycastle.util.arrays;

/**
 * the payload sent/received during the second round of a j-pake exchange.
 * <p/>
 * <p/>
 * each {@link jpakeparticipant} creates and sends an instance
 * of this payload to the other {@link jpakeparticipant}.
 * the payload to send should be created via
 * {@link jpakeparticipant#createround2payloadtosend()}
 * <p/>
 * <p/>
 * each {@link jpakeparticipant} must also validate the payload
 * received from the other {@link jpakeparticipant}.
 * the received payload should be validated via
 * {@link jpakeparticipant#validateround2payloadreceived(jpakeround2payload)}
 * <p/>
 */
public class jpakeround2payload
{
    /**
     * the id of the {@link jpakeparticipant} who created/sent this payload.
     */
    private final string participantid;

    /**
     * the value of a, as computed during round 2.
     */
    private final biginteger a;

    /**
     * the zero knowledge proof for x2 * s.
     * <p/>
     * this is a two element array, containing {g^v, r} for x2 * s.
     */
    private final biginteger[] knowledgeproofforx2s;

    public jpakeround2payload(
        string participantid,
        biginteger a,
        biginteger[] knowledgeproofforx2s)
    {
        jpakeutil.validatenotnull(participantid, "participantid");
        jpakeutil.validatenotnull(a, "a");
        jpakeutil.validatenotnull(knowledgeproofforx2s, "knowledgeproofforx2s");

        this.participantid = participantid;
        this.a = a;
        this.knowledgeproofforx2s = arrays.copyof(knowledgeproofforx2s, knowledgeproofforx2s.length);
    }

    public string getparticipantid()
    {
        return participantid;
    }

    public biginteger geta()
    {
        return a;
    }

    public biginteger[] getknowledgeproofforx2s()
    {
        return arrays.copyof(knowledgeproofforx2s, knowledgeproofforx2s.length);
    }

}
