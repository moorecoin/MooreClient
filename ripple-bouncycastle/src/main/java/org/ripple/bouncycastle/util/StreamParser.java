package org.ripple.bouncycastle.util;

import java.util.collection;

public interface streamparser
{
    object read() throws streamparsingexception;

    collection readall() throws streamparsingexception;
}
