package org.moorecoinlab.crypto.sjcljson;

public class jsescape {
    public static string unescape(string escaped) {
        int length = escaped.length();
        int i = 0;
        stringbuilder sb = new stringbuilder(escaped.length() / 2);

        while (i < length) {
            char n = escaped.charat(i++);
            if (n != '%') {
                sb.append(n);
            } else {
                n = escaped.charat(i++);
                int code;

                if (n == 'u') {
                    string slice = escaped.substring(i, i + 4);
                    code = integer.valueof(slice, 16);
                    i+=4;
                }  else {
                    string slice = escaped.substring(i-1, ++i);
                    code = integer.valueof(slice, 16);
                }
                sb.append((char) code);
            }
        }

        return sb.tostring();
    }

    public static string escape(string raw) {
        int length = raw.length();
        int i = 0;
        stringbuilder sb = new stringbuilder(raw.length() / 2);

        while (i < length) {
            char c = raw.charat(i++);

            if (isletterordigit(c) || isescapeexempt(c)) {
                sb.append(c);
            } else {
                int i1 = raw.codepointat(i-1);
                string escape = integer.tohexstring(i1);

                sb.append('%');

                if (escape.length() > 2) {
                    sb.append('u');
                }
                sb.append(escape.touppercase());

            }
        }

        return sb.tostring();
    }

    private static boolean isletterordigit(char ch) {
        return (ch >= 'a' && ch <= 'z') ||
               (ch >= 'a' && ch <= 'z') ||
               (ch >= '0' && ch <= '9');
    }

    private static boolean isescapeexempt(char c) {
        switch (c) {
            case '*':
            case  '@':
            case '-':
            case '_':
            case '+':
            case '.':
            case '/':
                return true;
            default:
                return false;
        }
    }
}
