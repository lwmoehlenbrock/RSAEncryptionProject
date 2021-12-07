import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class RSAEncryption {


    //I did this before realizing BigInteger had the BigInteger.ONE field etc.
    static BigInteger one = new BigInteger("1");
    static BigInteger two = new BigInteger("2");
    static BigInteger zero = new BigInteger("0");

    public static void main(String[] args) {

        //Generate a private/public key pair. keys[0] is n, keys[1] is e, and keys[2] is d
        BigInteger[] keys = GenerateKeys(512);

        String m = "Hello World! I guess for this to work I need to make sure this string is large enough or else it won't get broken down into smaller substrings. This should be the proper length I would assume... The only way to tell is if I add a lot more to this string so let me ramble. I'm glad I seem to have figured it out because for some reason converting from string to byte[] to BigInteger then doing the modular exponentiation then back to byte[] then back to string and so forth just was producing gibberish but this seems to be working! The number of bytes in this string is 739 which means it must be broken down 12 times for a 512 bit modulus. I guess the best way to tell would be to print out the size of the ArrayList returned by Encipher.";

        //for making sure the Encipher method is breaking down the string into blocks properly
        byte[] mByte = m.getBytes(StandardCharsets.UTF_8);
        System.out.println(mByte.length);

        //the ciphertext is output as an ArrayList of BigIntegers, each corresponding to a block of the original message
        ArrayList<BigInteger> c = Encipher(m, keys[1], keys[0]);
        System.out.println(c.size());
        System.out.println(Decipher(c, keys[2], keys[0]));


    }

    public static SecureRandom rng = new SecureRandom();
    public static BigInteger lastA = new BigInteger("2");

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

    public static BigInteger GeneratePrime(int power, int iterations){
        BigInteger upperLimit = new BigInteger("2").pow(power).subtract(new BigInteger("1"));
        BigInteger p = new BigInteger("2");
        do {
            p = new BigInteger(upperLimit.bitLength(), rng);
        } while (!MillerRabin(p, iterations));
        return p;
    }

    public static BigInteger GeneratePrimeGuaranteeBits(int power, int iterations){
        BigInteger upperLimit = new BigInteger("2").pow(power);
        BigInteger p = new BigInteger("2");
        do {
            p = RandRange(new BigInteger("2").pow(power - 1), new BigInteger("2").pow(power).subtract(new BigInteger("1")));
        } while (!MillerRabin(p, iterations));
        return p;
    }

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

    public static BigInteger RandRange(BigInteger lowerBound, BigInteger upperBound){

        BigInteger randValue;

        do {
            randValue = new BigInteger(upperBound.bitLength(), rng);
        }while(randValue.compareTo(lowerBound) <=0);

        return randValue;
    }

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
