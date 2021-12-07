import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.SQLOutput;
import java.util.ArrayList;
import java.util.Arrays;

public class RSAEncryption {


    //I did this before realizing BigInteger class had the BigInteger.ONE field etc.
    static BigInteger one = new BigInteger("1");
    static BigInteger two = new BigInteger("2");
    static BigInteger zero = new BigInteger("0");

    public static void main(String[] args) {
        int n;
        if(args[0].equals("keys")){
            try {
                n = Integer.parseInt(args[1]);
                String fileName = args[2];
                File keys = new File(fileName);
                try{
                    if(keys.createNewFile()){
                        BigInteger[] generatedKeys = GenerateKeys(n);
                        FileWriter keysWriter = new FileWriter(fileName);
                        keysWriter.write("RSA Modulus: " + generatedKeys[0] + "\n");
                        keysWriter.write("RSA Public Exponent: " + generatedKeys[1] + "\n");
                        keysWriter.write("RSA Private Exponent: " + generatedKeys[2] + "\n");
                        keysWriter.close();
                    }
                    else {
                        System.out.println("File " + fileName + "already exists.");
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            catch(Exception e){
                usage();
            }
        }
        else if(args[0].equals("encrypt")){
            String messageFileName = args[1];
            String ciphertextFileName = args[2];
            BigInteger publicKey = new BigInteger(args[3]);
            BigInteger modulus = new BigInteger(args[4]);
            String message;
            try{
                File cipherText = new File(ciphertextFileName);
                BufferedReader br = new BufferedReader(new FileReader(messageFileName));
                try {
                    StringBuilder sb = new StringBuilder();
                    String line = br.readLine();

                    while (line != null) {
                        sb.append(line);
                        line = br.readLine();
                    }
                    message = sb.toString();
                } finally {
                    br.close();
                }
                try {
                    if (cipherText.createNewFile()) {
                        ArrayList<BigInteger> cipherTextBlocks = Encipher(message, publicKey, modulus);
                        FileWriter cipherWriter = new FileWriter(cipherText);
                        for(BigInteger i : cipherTextBlocks) {
                            cipherWriter.write(i + "\n");
                        }
                        cipherWriter.close();
                    } else {
                        System.out.println("File " + ciphertextFileName + "already exists.");
                    }
                }catch (IOException e) {
                    e.printStackTrace();
                }
            }catch(Exception e){
                usage();
            }
        }
        else if(args[0].equals("decrypt")) {
            String cipherFileName = args[1];
            String messageFileName = args[2];
            BigInteger privateKey = new BigInteger(args[3]);
            BigInteger modulus = new BigInteger(args[4]);
            String message;
            ArrayList<BigInteger> ciphertextBlocks = new ArrayList<BigInteger>();
            try {
                File cipherText = new File(cipherFileName);
                BufferedReader br = new BufferedReader(new FileReader(cipherFileName));
                try {
                    String line = br.readLine();
                    while (line != null) {
                        ciphertextBlocks.add(new BigInteger(line));
                        line = br.readLine();
                    }
                } finally {
                    br.close();
                }
                try {
                    File messageText = new File(messageFileName);
                    if (messageText.createNewFile()) {
                        message = Decipher(ciphertextBlocks, privateKey, modulus);
                        FileWriter messageWriter = new FileWriter(messageText);
                        messageWriter.write(message);
                        messageWriter.close();
                    } else {
                        System.out.println("File " + messageFileName + "already exists.");
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } catch (Exception e) {
                usage();
            }
        }
        else{
            usage();
        }
    }

    public static SecureRandom rng = new SecureRandom();
    public static BigInteger lastA = new BigInteger("2");

    public static void usage(){
        System.out.println("To generate a pair of RSA keys use the following arguments:");
        System.out.println("java RSAEncryption keys n outputFile.txt");
        System.out.println("n - number of bits for the desired RSA modulus");
        System.out.println("outputFile - the name of the file that will be created to store the keys");
        System.out.println("");
        System.out.println("To encrypt a message use the following arguments:");
        System.out.println("java RSAEncryption encrypt message.txt cipher.txt e n");
        System.out.println("message - the name of the file containing the message to be encrypted");
        System.out.println("cipher - the name of the file that will be created to store the ciphertext");
        System.out.println("e - the public RSA key");
        System.out.println("n - the RSA modulus");
        System.out.println("");
        System.out.println("To decrypt a message use the following arguments:");
        System.out.println("java RSAEncryption decrypt cipher.txt message.txt d n");
        System.out.println("cipher - the name of the file containing the ciphertext to be decrypted");
        System.out.println("message - the name of the file that will be created to store the decrypted message");
        System.out.println("d - the private RSA key");
        System.out.println("n - the RSA modulus");
    }

    //This was just a method I had for trying to find composite numbers that passed a certain number of miller rabin iterations, it's not important to the actual RSA implementation
    public static boolean PrimeChecker(BigInteger n){
        for(BigInteger i = new BigInteger("2"); i.pow(2).compareTo(n) <=0; i = i.add(new BigInteger("1"))){
            if(n.mod(i).equals(new BigInteger("0"))){
                return false;
            }
        }
        return true;
    }

    //Generates two primes p and q and returns an array of BigIntegers with {n, e, d} for the public/private key pair, uses 40 miller-rabin iterations for generating the primes
    public static BigInteger[] GenerateKeys(int bits){
        int primeBits = bits/2;
        BigInteger e = new BigInteger("65537");

        BigInteger p = GeneratePrimeGuaranteeBits(primeBits, 40);
        BigInteger q = GeneratePrimeGuaranteeBits(primeBits, 40);

        BigInteger n = p.multiply(q);
        BigInteger totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger d = e.modInverse(totient);
        BigInteger[] keys = {n, e, d};
        return keys;
    }

    //Encrypts a message and outputs the ciphertext as blocks of BigIntegers
    public static ArrayList<BigInteger> Encipher(String m, BigInteger e, BigInteger n){
        int numBytes = n.bitLength()/8;
        byte[] mBytes = m.getBytes(StandardCharsets.UTF_8);
        int length = mBytes.length;
        StringBuilder cBuilder = new StringBuilder();
        ArrayList<BigInteger> cIntList = new ArrayList<BigInteger>();
        byte[] mByteIndex;

        for(int i = 0; i < length; i+=numBytes){
            if(i + numBytes > length){
                mByteIndex = Arrays.copyOfRange(mBytes, i, mBytes.length);
            }
            else{
                mByteIndex = Arrays.copyOfRange(mBytes, i, i + numBytes);
            }
            BigInteger mIntIndex = new BigInteger(mByteIndex);
            BigInteger cIntIndex = mIntIndex.modPow(e, n);
            cIntList.add(cIntIndex);
        }
        return cIntList;

    }

    //Decrypts ciphertext from an ArrayList of blocks that were originally enciphered with this program
    public static String Decipher(ArrayList<BigInteger> c, BigInteger d, BigInteger n){

        int numBytes = n.bitLength()/8;
        int length = c.size();
        StringBuilder mBuilder = new StringBuilder();
        byte[] cByteIndex;

        for (BigInteger i: c) {
            BigInteger mIntIndex = i.modPow(d, n);
            mBuilder.append(new String(mIntIndex.toByteArray()));
        }

        String m = mBuilder.toString();
        return m;
    }

    //generates a strong probable prime number less than 2^power
    public static BigInteger GeneratePrime(int power, int iterations){
        BigInteger upperLimit = new BigInteger("2").pow(power).subtract(new BigInteger("1"));
        BigInteger p = new BigInteger("2");
        do {
            p = new BigInteger(upperLimit.bitLength(), rng);
        } while (!MillerRabin(p, iterations));
        return p;
    }

    //generates a strong probable prime number with the specified number of bits
    public static BigInteger GeneratePrimeGuaranteeBits(int power, int iterations){
        BigInteger upperLimit = new BigInteger("2").pow(power);
        BigInteger p = new BigInteger("2");
        do {
            p = RandRange(new BigInteger("2").pow(power - 1), new BigInteger("2").pow(power).subtract(new BigInteger("1")));
        } while (!MillerRabin(p, iterations));
        return p;
    }

    //Wrapper function for performing k miller-rabin iterations for testing a number for primality
    public static boolean MillerRabin(BigInteger n, int k){

        for(int i = 0; i < k; i++){
            BigInteger a = RandRange(new BigInteger("2"), n.subtract(new BigInteger("1")));

            //If, at any point during the k iterations, the miller-rabin test fails, then the number is not prime so we return false for the number n being tested for primality
            if(!SingleMillerRabin(n, a)){
                return false;
            }
            lastA = a;
        }

        return true;
    }


    //Based on Fermat's Little Theorem -----> a^(n-1) mod n = 1 for a prime number n and 1 < a < n
    //This can be simplified to               a^(n-1) - 1 mod n = 0
    //Meaning that a^(n-1) - 1 is divisible by n
    //We can factor this value by using the difference of 2 squares until we get a value of a^[(n-1)/k] that is not divisible by 2
    //This gives us the factors {a^[(n-1)/k] - 1}*{a^[(n-1)/k] + 1}*{a^[(n-1)/(k/2)] + 1}* . . . *{a^(n-1) + 1}
    //One of these factors must be divisible by n or else n is not prime
    public static boolean SingleMillerRabin(BigInteger n, BigInteger a){

        BigInteger exp = n.subtract(one);

        //keep dividing exp by 2 until it is odd
        while(exp.mod(two).equals(zero)){
            exp = exp.shiftRight(1);
        }

        //equivalent to {a^[(n-1)/k] - 1} mod n = 0
        if(a.modPow(exp, n).equals(one)){
            return true;
        }

        //checking the rest of the factors of a^(n-1) - 1
        while(exp.compareTo(n.subtract(one)) < 0){
            if(a.modPow(exp, n).compareTo(n.subtract(one)) == 0){//a^exp mod n = -1
                return true;
            }
            exp = exp.shiftLeft(1);
        }

        return false;

    }

    //Generates a random number between the lower bound and upper bound
    public static BigInteger RandRange(BigInteger lowerBound, BigInteger upperBound){

        BigInteger randValue;

        do {
            randValue = new BigInteger(upperBound.bitLength(), rng);
        }while(randValue.compareTo(lowerBound) <=0);

        return randValue;
    }

    //This method was just something I made when I was curious about composite numbers that would pass the miller-rabin test
    //for a large number of bases, it doesn't really have any relevance to the project
    public static void MillerRabinCheck(int power, int iterations){
        BigInteger p;
        int counter = 0;
        int check = 1;
        do{
            p = GeneratePrime(power, iterations);
            counter++;
            if(counter == check*10){
                check*=10;
                System.out.println(counter);
            }
        } while(PrimeChecker(p));


        System.out.println(p);
        System.out.println(lastA);
        System.out.println(counter);
    }




}
