package app.attestation.server;

import com.almworks.sqlite4java.SQLiteBackup;
import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import java.io.File;

class Maintenance implements Runnable {
    private static final long WAIT_MS = 24 * 60 * 60 * 1000;
    private static final int DELETE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

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

            System.err.println("maintenance");

            try {
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
            } catch (final SQLiteException e) {
                e.printStackTrace();
            } finally {
                try {
                    deleteDeletedDevices.reset();
                    selectBackups.reset();
                    updateBackups.reset();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
