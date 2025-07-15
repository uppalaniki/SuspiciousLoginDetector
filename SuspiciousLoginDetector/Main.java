import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        LoginTracker tracker = new LoginTracker();
        Scanner scanner = new Scanner(System.in);

        System.out.println("Suspicious Login Detector (Java with Records + CSV Logging)");


        //Loop to read login attempts until user types 'exit'
        while (true) {
            System.out.print("\nEnter username (or 'exit'): ");
            String user = scanner.nextLine();
            if (user.equalsIgnoreCase("exit")) break;

            System.out.print("Enter country: ");
            String country = scanner.nextLine(); 

            tracker.addLogin(user, country); //Recording login attempt
        }

        tracker.printReport(); //Printing suspicious activity report
        System.out.println("Program ended.");
    }
}
