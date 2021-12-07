# RSAEncryptionProject
An RSA implementation created for my ECS 235 term project. This implementation is not intended for use as a secure cryptographic tool and was merely implemented to learn more about RSA encryption.

Compiling and usage:
First, after downloading the code change directory to (directory where the project is)/RSAEncryptionProject/src/main/java and compile the program with: 
javac RSAEncryption.java
Then to generate a pair of keys use the following arguments:
java RSAEncryption keys n outputFile.txt
Where n is the desired number of bits for the RSA modulus and outputFile.txt is the name of the file that the program will create and write the public and private keys and the modulus.
Then to encrypt a message use the following arguments:
java RSAEncryption encrypt message.txt cipher.txt e n
Where message.txt is the file containing the message you want to encrypt, cipher.txt is the file that will be created and will have the ciphertext written to it, e is the public exponent and n is the modulus.
Then to decrypt a message use the following arguments:
java RSAEncryption decrypt cipher.txt message.txt d n
Where cipher.txt is the ciphertext that was created using the encrypt argument, message.txt is the file that will be created to store the decrypted message, d is the private exponent and n is the modulus.
Unless a path is specified, the program will look for the existing text files in the /RSAEncryptionProject/src/main/java directory and will also create the output files in that directory.

Below are screenshots showing the process of compiling, generating keys, encrypting a message, and decrypting the ciphertext:


![Compiling the program:](https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/compile.PNG)

message.txt has already been created, ready to encrypt once we generate some keys:
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/folderaftercompile.PNG)
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/message.PNG)

Generating some keys:
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/keys.PNG)

The file mykeys has been created in the current directory:
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/folderafterkeys.PNG)
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/mykeys.PNG)

Now we use the public exponent and the modulus from mykeys.txt to encrypt message.txt:
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/encrypt.PNG)

The file cipher.txt has been created in the current directory:
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/folderafterencrypt.PNG)
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/cipher.PNG)

Now we use the private exponent and the modulus from mykeys.txt to decrypt cipher.txt:
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/decrypt.PNG)

The file decryptedmessage.txt has been created in the current directory, and it matches the original message!:
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/folderafterdecrypt.PNG)
!(https://github.com/lwmoehlenbrock/RSAEncryptionProject/blob/master/decryptedmessage.PNG)

