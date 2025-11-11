package performance;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PerformanceLogger {
    private static final String LOG_DIR = "performance";
    private final BufferedWriter writer;

    public PerformanceLogger(String systemName) throws IOException {
        Files.createDirectories(Paths.get(LOG_DIR));
        String filename = LOG_DIR + "/" + systemName.toLowerCase() + "_performance.csv";

        boolean fileExists = Files.exists(Paths.get(filename));
        this.writer = new BufferedWriter(new FileWriter(filename, true));

        if (!fileExists) {
            writer.write("operation,duration_ms\n");
            writer.flush();
        }
    }

    public synchronized void log(String operation, double durationMs) {
        try {
            String line = String.format("%s,%.3f\n", operation, durationMs);

            writer.write(line);
            writer.flush();

        } catch (IOException e) {
            System.err.println("Error while logging: " + e.getMessage());
        }
    }

    public void close() {
        try {
            if (writer != null) {
                writer.close();
            }
        } catch (IOException e) {
            System.err.println("Error while closing: " + e.getMessage());
        }
    }

    public static class Timer {
        private long startTime;

        public void start() {
            startTime = System.nanoTime();
        }

        public double stopMs() {
            long endTime = System.nanoTime();
            return (endTime - startTime) / 1_000_000.0;
        }
    }
}
