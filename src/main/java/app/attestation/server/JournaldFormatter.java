package app.attestation.server;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;

class JournaldFormatter extends Formatter {
    private static final int LEVEL_EMERG = 0;
    private static final int LEVEL_ALERT = 1;
    private static final int LEVEL_CRIT = 2;
    private static final int LEVEL_ERR = 3;
    private static final int LEVEL_WARNING = 4;
    private static final int LEVEL_NOTICE = 5;
    private static final int LEVEL_INFO = 6;
    private static final int LEVEL_DEBUG = 7;

    private static int toSyslogLevel(final Level level) {
        final int value = level.intValue();
        if (value >= 1300) {
            return LEVEL_EMERG;
        }
        if (value >= 1200) {
            return LEVEL_ALERT;
        }
        if (value >= 1100) {
            return LEVEL_CRIT;
        }
        // Level.SEVERE 1000
        if (value >= 1000) {
            return LEVEL_ERR;
        }
        // Level.WARNING 900
        if (value >= 900) {
            return LEVEL_WARNING;
        }
        if (value >= 850) {
            return LEVEL_NOTICE;
        }
        // Level.INFO 800
        if (value >= 800) {
            return LEVEL_INFO;
        }
        // Level.CONFIG 700
        // Level.FINE 500
        // Level.FINER 400
        // Level.FINEST 300
        return LEVEL_DEBUG;
    }

    @Override
    public synchronized String format(LogRecord record) {
        String source;
        if (record.getSourceClassName() != null) {
            source = record.getSourceClassName();
            if (record.getSourceMethodName() != null) {
               source += " " + record.getSourceMethodName();
            }
        } else {
            source = record.getLoggerName();
        }
        final int level = toSyslogLevel(record.getLevel());
        final String newline = "\n<" + toSyslogLevel(record.getLevel()) + ">";
        final String message = formatMessage(record).replace("\n", newline);
        String throwable = "";
        if (record.getThrown() != null) {
            final StringWriter sw = new StringWriter();
            final PrintWriter pw = new PrintWriter(sw);
            pw.println();
            record.getThrown().printStackTrace(pw);
            pw.close();
            throwable = sw.toString().replace("\n", newline);
        }
        return "<%s>%s: %s%s\n".formatted(level, source, message, throwable);
    }
}
