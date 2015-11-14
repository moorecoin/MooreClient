package org.ripple.bouncycastle.crypto.tls;

public interface tlspeer
{

    /**
     * this method will be called when an alert is raised by the protocol.
     *
     * @param alertlevel       {@link alertlevel}
     * @param alertdescription {@link alertdescription}
     * @param message          a human-readable message explaining what caused this alert. may be null.
     * @param cause            the exception that caused this alert to be raised. may be null.
     */
    void notifyalertraised(short alertlevel, short alertdescription, string message, exception cause);

    /**
     * this method will be called when an alert is received from the remote peer.
     *
     * @param alertlevel       {@link alertlevel}
     * @param alertdescription {@link alertdescription}
     */
    void notifyalertreceived(short alertlevel, short alertdescription);
}
