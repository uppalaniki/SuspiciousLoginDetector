import java.time.LocalDateTime;
/**
 * Record representing a login attempt event.
 * 
 * This immutable record stores:
 * - username: The user who attempted to log in.
 * - country: The country from which the login attempt was made.
 * - timestamp: The date and time when the login attempt occurred.
 */
public record LoginAttempt(String username, String country, LocalDateTime timestamp) {}
