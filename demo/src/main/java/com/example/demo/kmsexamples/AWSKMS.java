package com.example.demo.kmsexamples;

import java.io.*;

import com.amazonaws.encryptionsdk.*;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class AWSKMS {

    @RequestMapping(value = "/newFile", method = RequestMethod.POST)
    public String newFile() {
//      File file = new File("D:/home/site/wwwroot/testfile");
//        File file = new File("src/main/resources/templates/");
//        file.mkdirs();

        String path = "src/main/resources/templates/a.txt";
        String data = "pooja desur 12345";
        try {
//          BufferedWriter writer = new BufferedWriter( new FileWriter("D:/home/site/wwwroot/testfile/cout.txt") );
            BufferedWriter writer = new BufferedWriter(new FileWriter(path));
            writer.write(data);
            writer.flush();
            writer.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return "hello world";
    }

    public void writeFile(String data, String filepath) throws IOException {

        String path = filepath;

        BufferedWriter writer = new BufferedWriter( new FileWriter( path ) );
        writer.write( data );

        writer.flush();
        writer.close();
    }

    @RequestMapping(value = "/readFile", method = RequestMethod.GET)
    public String readFile(String filename) {

        File file = new File(filename);

        System.out.println("Reading file...");

        BufferedReader reader = null;
        StringBuilder buffer = new StringBuilder();

        try {
            reader = new BufferedReader( new FileReader( file ) );
            String text;

            while ( ( text = reader.readLine() ) != null ) {
                buffer.append( text );
            }
        } catch ( IOException e ) {
            e.printStackTrace();
        } finally {
            try {
                if ( reader != null ) {
                    reader.close();
                }
            } catch ( IOException e ) {
                e.printStackTrace();
            }
        }

        return buffer.toString();
    }
    
    // put your KMS CMK key ARN here
    private static final String keyArn = "";

    /*

    Reads source data from data.txt and encrypts and decrypts data using AWS KMS using CMKs created on console.
    Encrypted data is written to encrypted.txt
    Decrypted data is written to decrypted.txt

     */
    @RequestMapping(value = "/encryptAndDecrypt", method = RequestMethod.GET)
    public String encryptAndDecrypt() throws IOException {

        System.out.println("\n\n\n\n");

        // 1. Reading data from source file to be encrypted
        String data = readFile("src/main/resources/templates/data.txt");
        System.out.println("Data from source file: "+data);
        final byte[] EXAMPLE_DATA = data.getBytes(StandardCharsets.UTF_8);

        // 2. Instantiate the SDK
        final AwsCrypto crypto = AwsCrypto.standard();

        // 3. Getting the customer managed master key with created CMK keyARN
        final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder().buildStrict(keyArn);

        // 4. Set encryption context which gives more contextual information - public information,
        // but should remain the same during encryption and decryption
        final Map<String, String> encryptionContext = Collections.singletonMap("AwsKMSMasterKey",
                "In spring-boot application");

        // 5. Encrypting the data and writing it to output file encrypted.txt
        System.out.println("Encrypting data...");
        final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(keyProvider,
                EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();
        String encrypted = new String(ciphertext);
        System.out.println("Encrypted data: "+encrypted);
        System.out.println("Writing encrypted data to file...");
        this.writeFile(encrypted,"src/main/resources/templates/encrypted.txt" );
        System.out.println("Encrypted Successfully!");



        // 6. Decrypting the data returned after encryption and writing it to decrypted.txt
        System.out.println("\n\nDecrypting data...");
        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(keyProvider,
                ciphertext);
        String decrypted = new String(decryptResult.getResult());
        System.out.println("Decrypted data: "+decrypted);
        System.out.println("Writing decrypted data to file...");
        this.writeFile(decrypted, "src/main/resources/templates/decrypted.txt");

        // 7. Verify that the encryption context in the result contains the
        // encryption context supplied to the encryptData method. Because the
        // SDK can add values to the encryption context, don't require that
        // the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(
                        e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 8. Verify that the decrypted plaintext data matches the source plaintext data
        System.out.println("\n\nVerifying that the decrypted plaintext matches the original plaintext...");

        String data2 = readFile("src/main/resources/templates/data.txt");
        final byte[] EXAMPLE_DATA2 = data.getBytes(StandardCharsets.UTF_8);
        System.out.println("Source data: "+data2);
        System.out.println("Decrypted data: "+decrypted);

        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA2);
        System.out.println("Original data and decrypted data Matches.");
        System.out.println("Decrypted Successfully!");

        return "Encrypted and Decrypted Successfully!";
    }

    // algorithms for encryption outside AWS KMS
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    @RequestMapping(value = "/datakeyGeneration", method = RequestMethod.GET)
    public String dataKey() throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException {

        System.out.println("\n\n\n\n");

        // 1. Creating master key provider using KeyARN
        KmsMasterKeyProvider kmsMasterKeyProvider = KmsMasterKeyProvider.builder().buildStrict(keyArn);

        // 2. Proving encryption context - extra contextual information
        final Map<String, String> encryptionContext=Collections.singletonMap("AwsKmsMasterKey", "In spring-boot application");

        System.out.println("\n\nData Key Generation...");

        // 3. Creating Master Key
        MasterKeyRequest masterKeyRequest=MasterKeyRequest.newBuilder().build();
        List<KmsMasterKey> masterKeys=kmsMasterKeyProvider.getMasterKeysForEncryption(masterKeyRequest);
        MasterKey<KmsMasterKey> masterKey=masterKeys.get(0);
        System.out.println("=========Master Key========\n"+masterKey);
        System.out.println("=========Key Id========\n"+masterKey.getKeyId());
        System.out.println("=========Provider Id========\n"+masterKey.getProviderId());

        // 4. Generating symmetric data key from CMK that returns plaintext data key and encrypted data key
        // Data key generated can be used to encrypt data outisde KMS
        DataKey<KmsMasterKey> dataKey =  masterKey.generateDataKey(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256, encryptionContext);
        System.out.println("=========Encrypted Data Key Id========\n"+dataKey.getEncryptedDataKey());
        System.out.println("=========Data Key Id========\n"+dataKey.getKey());
        System.out.println("=========Data Key's Master Key Id========\n"+dataKey.getMasterKey());

        // 5. Saving encrypted Data key to encrypted_dataKey.txt
        final byte[] datakeyEncrypted = dataKey.getEncryptedDataKey();
        String encrypted = new String(datakeyEncrypted);
        this.writeFile(encrypted, "src/main/resources/templates/encrypted_dataKey.txt");

        return "Data key generated!";

        // 6. Encrypting data outside AWS KMS using generated Data key
//        //Creating a Cipher object
//        Cipher cipher = Cipher.getInstance("AES") ;
//        //Initializing a Cipher object
//        cipher.init(Cipher.ENCRYPT_MODE, dataKey.getKey());
//
//
////        //encrypting using public data key generated from CMK
////        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
////
////        //Initializing a Cipher object
////        cipher.init(Cipher.ENCRYPT_MODE, dataKey.getKey());
//
//        //Adding data to the cipher
//        String data = readFile("src/main/resources/templates/data.txt");
//        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
//
//        //encrypting the data
//        byte[] cipherText = cipher.doFinal(dataBytes);
//        String encrypted = new String(cipherText);
//
//        return encrypted;
    }

}



