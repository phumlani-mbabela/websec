/*
 * Class used for symetric encryption.
 */
package co.za.zwideheights.websec.encryption;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Phumlani Kaida Mbabela
 */
public class SymetricEncryption {

    public SymetricEncryption() {
    }
    
    /* This function is used to encrypt plain text. Geared for symetric encryption.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Plain text, text to be encypted.
     * @param   Key , e.g 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
     * @param   Encryption Algorithm Standard , AES
     * @return  Encrypted string.
     */
    public static String encrypt(String plainText, byte[] key, String algorithmStandard) {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        try {
            byte[] input = plainText.getBytes();
            Cipher c = Cipher.getInstance(algorithmStandard);
            SecretKeySpec k = new SecretKeySpec(key, algorithmStandard);
            c.init(Cipher.ENCRYPT_MODE, k);
            byte[] encryptedData = c.doFinal(input);
            return encryptedData.toString();
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            return null;
        } catch (NoSuchPaddingException nspe) {
            nspe.printStackTrace();
            return null;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException ibse) {
            ibse.printStackTrace();
            return null;
        } catch (BadPaddingException bpe) {
            bpe.printStackTrace();
            return null;
        }

    }

    /* This function is used to decrypt encrypted text. Geared for symetric encryption.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Encrypted text, text to be decrypted.
     * @param   Key , e.g 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
     * @param   Encryption Algorithm Standard , AES
     * @return  Decrypted string.
     */
    public static String decrypt(String plainText, byte[] key, String algorithmStandard) {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        try {
            byte[] input = plainText.getBytes();
            Cipher c = Cipher.getInstance(algorithmStandard);
            SecretKeySpec k = new SecretKeySpec(key, algorithmStandard);
            c.init(Cipher.DECRYPT_MODE, k);
            byte[] data = c.doFinal(input);
            return data.toString();
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            return null;
        } catch (NoSuchPaddingException nspe) {
            nspe.printStackTrace();
            return null;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException ibse) {
            ibse.printStackTrace();
            return null;
        } catch (BadPaddingException bpe) {
            bpe.printStackTrace();
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /* This function is used to encrypt plain text. Geared for symetric encryption.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Plain text, text to be encypted.
     * @return  Encrypted string.
     */
    public static String encryptDefault(String plainText) {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        try {
            byte[] input = plainText.getBytes();
            byte[] key = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
            Cipher c = Cipher.getInstance("AES");
            SecretKeySpec k = new SecretKeySpec(key, "AES");
            c.init(Cipher.ENCRYPT_MODE, k);
            byte[] encryptedData = c.doFinal(input);
            return encryptedData.toString();
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            return null;
        } catch (NoSuchPaddingException nspe) {
            nspe.printStackTrace();
            return null;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException ibse) {
            ibse.printStackTrace();
            return null;
        } catch (BadPaddingException bpe) {
            bpe.printStackTrace();
            return null;
        }

    }

    /* This function is used to decrypt encrypted text. Geared for symetric encryption.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Encrypted text, text to be decrypted.
     * @return  Decrypted string.
     */
    public static String decryptDefault(String plainText) {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        try {
            byte[] input = plainText.getBytes();
            byte[] key = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
            Cipher c = Cipher.getInstance("AES");
            SecretKeySpec k = new SecretKeySpec(key, "AES");
            c.init(Cipher.DECRYPT_MODE, k);
            byte[] data = c.doFinal(input);
            return data.toString();
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            return null;
        } catch (NoSuchPaddingException nspe) {
            nspe.printStackTrace();
            return null;
        } catch (InvalidKeyException ike) {
            ike.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException ibse) {
            ibse.printStackTrace();
            return null;
        } catch (BadPaddingException bpe) {
            bpe.printStackTrace();
            return null;
        }
    }
}
