import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

public class LoginTracker {
    //Map to store lists of login attempts for each username
    private final Map<String, List<LoginAttempt>> userLogins = new HashMap<>();

    //List to store alert messages for suspicious activities
    private final List<String> alerts = new ArrayList<>();

    //CSV filename where login attempts will be logged
    private final String csvFile = "logins.csv";

    /**
     * Constructor initializes the CSV log file with headers.
     * If the file cannot be created or written to, an error message is printed.
     */
    public LoginTracker() {
        try (FileWriter writer = new FileWriter(csvFile)) {
            //Write CSV header line
            writer.write("Username,Country,Timestamp\n");
        } catch (IOException e) {
            System.err.println("Error initializing log file: " + e.getMessage());
        }
    }

     /**
     * Records a login attempt for a user from a specified country at the current time.
     * The attempt is added to the internal tracking map, logged to CSV, and checked for suspicious activity.
     * 
     * @param username The username attempting login
     * @param country  The country from which the login is made
     */
    public void addLogin(String username, String country) {
        LocalDateTime now = LocalDateTime.now(); //Capturing current time
        LoginAttempt attempt = new LoginAttempt(username, country, now);

         //Ensuring the user has an entry in the map; create if absent
        userLogins.putIfAbsent(username, new ArrayList<>());
        List<LoginAttempt> logins = userLogins.get(username);
        
        //Adding this new login attempt to the user's login history
        logins.add(attempt);
        
        //Logging the attempt to CSV file
        logToCSV(attempt);

        //Checking for suspicious login activity based on recent logins
        checkSuspiciousActivity(username, country, now, logins);
    }

    /**
     * Append a login attempt record to the CSV file.
     * 
     * @param attempt The LoginAttempt to log
     */
    private void logToCSV(LoginAttempt attempt) {
        try (FileWriter writer = new FileWriter(csvFile, true)) { //'true' to append
            //Writing username, country, and timestamp as CSV line
            writer.write(attempt.username() + "," + attempt.country() + "," + attempt.timestamp() + "\n");
        } catch (IOException e) {
            System.err.println("Error writing to CSV: " + e.getMessage());
        }
    }

   /**
     * Checks the user's recent login attempts for suspicious activity:
     * 1. Login from different countries within 1 hour
     * 2. More than 3 logins within 1 minute
     * If suspicious behavior is detected, an alert is printed and stored.
     * 
     * @param username The username to check
     * @param country  The country of the current login
     * @param now      Timestamp of current login
     * @param logins   List of all login attempts for the user
     */
    private void checkSuspiciousActivity(String username, String country, LocalDateTime now, List<LoginAttempt> logins) {
        int recentCount = 0;  //Count of logins within 1 minute

        for (LoginAttempt previous : logins) {
            long minutesBetween = Duration.between(previous.timestamp(), now).toMinutes();

            //Checking if previous login was from a different country within last hour
            if (!previous.country().equals(country) && minutesBetween <= 60) {
                String alert = "[ALERT] User '" + username + "' changed country within 1 hour.";
                System.out.println(alert);
                alerts.add(alert);
                break; //Alerting once per suspicious event
            }

            //Counting how many logins happened within the last 1 minute
            if (minutesBetween <= 1) {
                recentCount++;
            }
        }

        // If more than 3 logins in 1 minute, trigger alert
        if (recentCount > 3) {
            String alert = "[ALERT] User '" + username + "' has more than 3 logins in 1 minute!";
            System.out.println(alert);
            alerts.add(alert);
        }
    }

   /**
     * Prints a summary report of all suspicious activities detected so far.
     * If none are detected, informs that no suspicious activity was found.
     */
    public void printReport() {
        System.out.println("\n=== Suspicious Activity Report ===");
        if (alerts.isEmpty()) {
            System.out.println("No suspicious activity detected.");
        } else {
            //Printng all collected alerts with numbering
            for (int i = 0; i < alerts.size(); i++) {
                System.out.println((i + 1) + ". " + alerts.get(i));
            }
        }
    }
}
