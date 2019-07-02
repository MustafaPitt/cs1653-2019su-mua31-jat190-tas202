import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

// Password class is for generating random passwords
class PW {

    private static List<Character> pwDictionary; //  add ascii integers desired to be in the random password

    PW( ){
        // init dict
        initList();
    }

    private void initList() {
        pwDictionary = new ArrayList<>();
        for (int i  = 48 ; i <= 57; i ++ ){ // add numeric char 0 to 9
            pwDictionary.add((char)i);
        }
        for (int i  = 97   ; i <= 122 ; i ++){ // add chars a to z
            pwDictionary.add((char)i);
        }
        for (int i  = 65     ; i <= 90  ; i ++){ // add chars A to Z
            pwDictionary.add((char)i);
        }

    }


    static String generate (int len){
        PW pw = new PW();
        StringBuilder sb = new StringBuilder(len);
        SecureRandom secureRandom = new SecureRandom();
        for(int i = 0 ; i < len ; i ++){
            // Generate random integers in range 0 to 999
            // get random index to get char from our dictionary
            int ranIndex = secureRandom.nextInt(pwDictionary.size());
            sb.append(pwDictionary.get(ranIndex));
        }
    return sb.toString();
    }

    public static void main (String [] args){
        // test random passwords strings

        for (int i = 0 ; i < 10 ; i ++)
            System.out.println(generate(10));

    }

}
