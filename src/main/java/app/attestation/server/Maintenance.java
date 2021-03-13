package app.attestation.server;

import com.almworks.sqlite4java.SQLiteBackup;
import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

class Maintenance implements Runnable {
    private static final long WAIT_MS = 24 * 60 * 60 * 1000;
    private static final int DELETE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
    private static final int KEEP_BACKUPS = 28;

    private static final Logger logger = Logger.getLogger(Maintenance.class.getName());

    @Override
    public void run() {
        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        final SQLiteStatement deleteDeletedDevices;
        final SQLiteStatement selectBackups;
        final SQLiteStatement updateBackups;
        try {
            AttestationServer.open(conn, false);
            deleteDeletedDevices = conn.prepare("DELETE FROM Devices WHERE deletionTime < ?");
            selectBackups = conn.prepare("SELECT value FROM Configuration WHERE key = 'backups'");
            updateBackups = conn.prepare("UPDATE Configuration SET value = value + 1 " +
                    "WHERE key = 'backups'");
        } catch (final SQLiteException e) {
            conn.dispose();
            throw new RuntimeException(e);
        }

        while (true) {
            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            logger.info("maintenance");

            try {
                conn.exec("ANALYZE");

                deleteDeletedDevices.bind(1, System.currentTimeMillis() - DELETE_EXPIRY_MS);
                deleteDeletedDevices.step();

                selectBackups.step();
                final long backups = selectBackups.columnLong(0);

                updateBackups.step();
                final SQLiteBackup backup = conn.initializeBackup(new File("backup/" + backups + ".db"));
                try {
                    backup.backupStep(-1);
                } finally {
                    backup.dispose();
                }

                final File[] backupFiles = new File("backup/").listFiles();
                for (final File backupFile : backupFiles) {
                    final String name = backupFile.getName();
                    try {
                        long backupIndex = Long.parseLong(name.split("\\.")[0]);
                        if (backupIndex <= backups - KEEP_BACKUPS) {
                            if (backupFile.delete()) {
                                logger.info("deleted old database backup: " + backupFile);
                            } else {
                                logger.warning("failed to delete database backup: " + name);
                            }
                        }
                    } catch (final NumberFormatException e) {
                        logger.warning("invalid database backup filename: " + name);
                    }
                }
            } catch (final SQLiteException e) {
                logger.log(Level.WARNING, "database error", e);
            } finally {
                try {
                    deleteDeletedDevices.reset();
                    selectBackups.reset();
                    updateBackups.reset();
                } catch (final SQLiteException e) {
                    logger.log(Level.WARNING, "database error", e);
                }
            }
        }
    }
}
