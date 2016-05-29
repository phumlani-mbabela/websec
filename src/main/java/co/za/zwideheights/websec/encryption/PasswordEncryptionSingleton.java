/*
 * This class is used to encrypt plain text. It's implemented using the singleton pattern.
 * Static methods will also do.
 */
package co.za.zwideheights.websec.encryption;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import sun.misc.BASE64Encoder;

/**
 *
 * @author Phumlani Kaida Mbabela
 */
public class PasswordEncryptionSingleton {

    private static PasswordEncryptionSingleton passwordEncryptionSingleton = null;

    /* Used to get an instance of PasswordEncryptionSingleton.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @return  an instance of PasswordEncryptionSingleton.
     */
    public static PasswordEncryptionSingleton getInstance() {
        if (passwordEncryptionSingleton == null) {
            passwordEncryptionSingleton = new PasswordEncryptionSingleton();
        }
        return passwordEncryptionSingleton;
    }

    /* This function is used to encrypt plain text.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Plain text, text to be encypted.
     * @param   Hash Algorithm, e.g Secure Hash Algorithm SHA.
     * @param   Character Encoding e.g UTF-8.
     * @throws  Throws Exception.
     * @return  Encrypted string.
     */
    public String encrypt(String plainText, String hashAlgorithm, String charEncoding) throws Exception {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        try {
            MessageDigest md = null;
            md = MessageDigest.getInstance(hashAlgorithm);
            md.update(plainText.getBytes(charEncoding));
            byte raw[] = md.digest();
            String hash = (new BASE64Encoder()).encode(raw);
            return hash;
        } catch (NoSuchAlgorithmException nsae) {
            throw new Exception(nsae.getMessage());
        } catch (UnsupportedEncodingException usee) {
            throw new Exception(usee.getMessage());
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    /* This function is used to encrypt plain text.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Plain text, text to be encypted.(SHA and UTF-8)
     * @throws  Throws Exception.
     * @return  Encrypted string.
     */
    public String encryptDefault(String plainText) throws Exception {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        try {
            MessageDigest md = null;
            md = MessageDigest.getInstance("SHA");
            md.update(plainText.getBytes("UTF-8"));
            byte raw[] = md.digest();
            String hash = (new BASE64Encoder()).encode(raw);
            return hash;
        } catch (NoSuchAlgorithmException nsae) {
            throw new Exception(nsae.getMessage());
        } catch (UnsupportedEncodingException usee) {
            throw new Exception(usee.getMessage());
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }
}