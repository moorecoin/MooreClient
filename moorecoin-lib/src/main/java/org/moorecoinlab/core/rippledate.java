package org.moorecoinlab.core;

import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.uint.uint32;

import java.util.calendar;
import java.util.date;
import java.util.gregoriancalendar;
import java.util.timezone;

//public class rippledate extends date implements serializedtype {
public class rippledate extends date {
    public static long ripple_epoch_seconds_offset = 0x386d4380;
    static {
        /**
         * magic constant tested and documented.
         *
         * seconds since the unix epoch from unix time (accounting leap years etc)
         * at 1/january/2000 gmt
         */
        gregoriancalendar cal = new gregoriancalendar(timezone.gettimezone("gmt"));
        cal.set(2000, calendar.january, 1, 0, 0, 0);
        long computed = cal.gettimeinmillis() / 1000;
        assertequals("1 jan 2000 00:00:00 gmt", cal.gettime().togmtstring()); // todo
        assertequals(rippledate.ripple_epoch_seconds_offset, computed);
    }

    private static void assertequals(string s, string s1) {
        if (!s.equals(s1)) throw new assertionerror(string.format("%s != %s", s, s1));
    }
    private static void assertequals(long a, long b) {
        if (a != b) throw new assertionerror(string.format("%s != %s", a, b));
    }

    private rippledate() {
        super();
    }
    private rippledate(long milliseconds) {
        super(milliseconds);
    }

    public long secondssincerippleepoch() {
        return ((this.gettime() / 1000) - ripple_epoch_seconds_offset);
    }
    public static rippledate fromsecondssincerippleepoch(number seconds) {
        return new rippledate((seconds.longvalue() + ripple_epoch_seconds_offset) * 1000);
    }
    public static rippledate fromparser(binaryparser parser) {
        uint32 uint32 = uint32.translate.fromparser(parser);
        return fromsecondssincerippleepoch(uint32);
    }
    public static rippledate now() {
        return new rippledate();
    }

/*    @override
    public object tojson() {
        return secondssincerippleepoch();
    }

    @override
    public byte[] tobytes() {
        return new uint32(secondssincerippleepoch()).tobytes();
    }

    @override
    public string tohex() {
        return new uint32(secondssincerippleepoch()).tohex();
    }

    @override
    public void tobytessink(bytessink to) {
        new uint32(secondssincerippleepoch()).tobytessink(to);
    }*/
}
