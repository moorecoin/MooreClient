package org.ripple.bouncycastle.x509.util;

import java.util.collection;

public interface streamparser
{
    object read() throws streamparsingexception;

    collection readall() throws streamparsingexception;
}
