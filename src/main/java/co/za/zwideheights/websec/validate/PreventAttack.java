/*
 * Class used for user input attacks.
 */
package co.za.zwideheights.websec.validate;

/**
 * @author Phumlani Kaida Mbabela
 */
public class PreventAttack {

    public PreventAttack() {
    }

    /* This function is used to remove cross site scripting code.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Plain text.
     * @return  Clean string.
     */
    public static String PreventCrossSiteScripting(String plainText) {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        plainText = plainText.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
        plainText = plainText.replaceAll("\\(", "&#40;").replaceAll("\\)", "&#41;");
        plainText = plainText.replaceAll("'", "&#39;");
        plainText = plainText.replaceAll("eval\\((.*)\\)", "");
        plainText = plainText.replaceAll("[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']", "\"\"");
        plainText = plainText.replaceAll("script", "");
        return plainText;
    }

    /* This function is used to remove SQL injection code.
     * @author  Phumlani Kaida Mbabela.
     * @version 1.2
     * @since   2011-08-28
     * @param   Plain text.
     * @return  Clean string.
     */
    public static String PreventSQLInjection(String plainText) {

        if (plainText == null || plainText.equals("")) {
            return null;
        }

        plainText = plainText.replaceAll("(?i)delete from ", "").replaceAll("(?i)insert into ", "").replaceAll("(?i)alter table ", "").replaceAll("(?i)drop *(table|column|database|index) ", "").replaceAll("(?i)truncate table ", "").replaceAll("(?i)select.*from ", "");
        /*
	        plainText = plainText.replaceAll("(?i)delete from ", "");
	        plainText = plainText.replaceAll("(?i)insert into ", "");
	        plainText = plainText.replaceAll("(?i)alter table ", "");
	        plainText = plainText.replaceAll("(?i)drop *(table|column|database|index) ", "");
	        plainText = plainText.replaceAll("(?i)truncate table ", "");
	        plainText = plainText.replaceAll("(?i)select.*from ", "");
        */
        return plainText;
    }
    
    
    /* @Rationale: Not every unicode character is a valid XML character.
     *           : We only need to pass valid XML characters.
     *           : The function is designed for XML Version 1.0 .
     *           : The problem is that the parser reports XML parsing error for a character less than 0x20.
     *           : The legal XML characters are TAB, CR, LF, 0x20 - 0xd7ff, 0xe000-0xfffd, and 0x10000-0x1ffff.
     *           : XML recomendations http://www.w3.org/TR/2000/REC-xml-20001006#NT-Char
     *           : Valid XML UNICODE Char :=  #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
     * @author   : Phumlani Kaaida Mbabela
     * @return   : Return a XML string with valid XML v1.0 characters.
     * @param    : XML string that needs to be preparsed.
     */
    public String removeNonValidUNICODECharInXML(String inputXML) {

        /* outXML(String) and current(char) are references to the output string and the current character */
        StringBuffer outXML = new StringBuffer();
        char currentChar;

        /* Assertion > Test if the input is null or empty and return an empty string. */
        if ((inputXML == null) || (inputXML.equals(""))) {
            return "";
        }

        /* Below is a forloop, it inspects characters 1 by 1 and adds only the valid XML characters
         * Valid XML UNICODE Char :=  #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
         * References : http://www.w3.org/TR/2000/REC-xml-20001006#NT-Char
         */
        for (int i = 0; i < inputXML.length(); i++) {
            currentChar = inputXML.charAt(i);
            if ((currentChar == 0x9) ||
                    (currentChar == 0xA) ||
                    (currentChar == 0xD) ||
                    ((currentChar >= 0x20) && (currentChar <= 0xD7FF)) ||
                    ((currentChar >= 0xE000) && (currentChar <= 0xFFFD)) ||
                    ((currentChar >= 0x10000) && (currentChar <= 0x10FFFF))) {
                outXML.append(currentChar);
            }
        }
        return outXML.toString();
    }
    
    
}
