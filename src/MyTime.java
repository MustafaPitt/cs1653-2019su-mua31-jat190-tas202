import java.time.LocalTime;

public class MyTime {

    public static void main (String [] args){
        System.out.println( LocalTime.now().plusHours(1));
    }

    public static LocalTime setDurationInHours(int hours){
        return LocalTime.now().plusHours(hours);
    }
    public static LocalTime setDurationInMint(int mint){
        return LocalTime.now().plusMinutes(mint);
    }

    public static boolean isExpired(LocalTime inputTime){
        return inputTime.isBefore(LocalTime.now());
    }


}
