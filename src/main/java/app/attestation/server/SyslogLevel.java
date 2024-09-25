package app.attestation.server;

import java.util.logging.Level;

public class SyslogLevel extends Level {
    protected SyslogLevel(final String name, final int value) {
        super(name, value);
    }

    static final Level EMERG = new SyslogLevel("EMERG", 1300);
    static final Level ALERT = new SyslogLevel("ALERT", 1200);
    static final Level CRIT = new SyslogLevel("CRIT", 1100);
    static final Level ERR = Level.SEVERE; // 1000
    static final Level WARNING = Level.WARNING; // 900
    static final Level NOTICE = new SyslogLevel("NOTICE", 850);
    static final Level INFO = Level.INFO; // 800
    // Level.CONFIG is 700
    // Level.FINE is 500
    // Level.FINER is 400
    static final Level DEBUG = Level.FINEST; // 300
}
