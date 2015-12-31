import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class PJ1 {
    
    static String CBCresidue;

    public static void main(String[] args) {
        String m=   "495AF5C7C3852A49285789D04827590489D94810AE568940";
        String key ="1948FAD429B98C38";
        String IV = "204859FC3AD21134";
        
        //String m=   "87878787878787878787878787878787";
        //String key ="0E329232EA6D0D73";
        //String IV = "0000000000000000";
        
        
        String crypt=CBC(m,key,IV);//Run CBC
        System.out.println("\tCBC:\nPlaintext:\t"+m+"\nCrypt:\t\t"+crypt);
        
        System.out.println("\n\tCBCresidue:\nplaintext:\t" + m);
        String residue = CBCresidue(m,key,IV);
        System.out.println("Residue: \t"+residue);
        
        System.out.println("\tCBC with residue encryption:\nplaintext:\t"+m );
        System.out.println("Crypt:\t\t"+CBCresCrypt(m,key,IV));
        
        crypt=OFB(m,key,IV,4);//Run OFB
        System.out.println("\n\tOFB:\nPlaintext:\t"+m+"\nCrypt:\t\t"+crypt);
        
        crypt=CFB(m,key,IV,4);//Run CFB
        System.out.println("\n\tCFB:\nPlaintext:\t"+m+"\nCrypt:\t\t"+crypt);
    }
    
    /*************************************************************************
     * 
     *                               CBC 
     *
     *************************************************************************/
    public static String CBC(String message, String key, String IV){
        byte[] crypt;               //Will hold final crypt message
        byte[] iVec = new byte[8];  //Holds IV for DES
        byte[] DESin = new byte[8]; //Holds DES input
        byte[] DESout = new byte[8];//Holds DES output
        byte[] keyArr = new byte[8];//Byte array of key for DES input
        int newLen=message.length();//Length of string if no padding is needed
        if(message.length()%16 !=0) //check if padding is needed
            newLen = message.length() + 16 - message.length()%16;
        char[] charArr = new char[newLen];//apply padding
        byte[] plain = new byte[newLen/2];
        crypt = new byte[newLen/2];
        
        int j=0;
        for (j=0;j<message.length();j++) //give padding
            charArr[j]=message.charAt(j);//Copy over to Char Array
        for(;j<newLen;j++)
            charArr[j]='0';              //apply 0 to padding
        
        plain = stringToByte(new String(charArr),charArr.length);       
        keyArr = stringToByte(key,16);
        iVec = stringToByte(IV,16);
        
        //                        START ENCRYPTION
        for(int i=0;i<(plain.length/8);i++){ //Repeat for every 8 byte block
            for(int b=0;b<8;b++){
                DESin[b]=(byte)(plain[(8*i) + b]^iVec[b]);//  PLAIN XOR IV
            }
            DESout = DES(DESin,keyArr); //      RUN DES
            for(int b=0;b<8;b++){
                crypt[(8*i)+b]=DESout[b]; //Output the crypt to final byte[]
                iVec[b]=DESout[b];//DESout set to next IV
            }
        }
        CBCresidue = byteArrayToHex(iVec);
        return byteArrayToHex(crypt);
    }
    /*************************************************************************
     * 
     *                           CBC RESIDUE  
     *
     *************************************************************************/
    public static String CBCresidue(String message, String key, String IV){
        CBCresidue = "";
        System.out.println("Ciphertext: \t" + CBC(message, key, IV));
        return CBCresidue;
        
    }
     /*************************************************************************
     * 
     *                           CBC RESIDUE ENCRYPTED
     *
     *************************************************************************/
    public static String CBCresCrypt(String message, String key, String IV){
        CBCresidue = "";
        String crypt;
        byte[] keyArr = stringToByte(key,16);
        
        crypt=CBC(message, key, IV); //Get the CBC crypt of message from CBC
        byte[] lastBlock = stringToByte(CBCresidue,16); //get the CBCresidue
        byte[] orRes = new byte[8]; //New byte[] to hold XOR of res^res
        for(int b=0;b<8;b++){
            orRes[b]=(byte)(lastBlock[b]^lastBlock[b]);
        }
        crypt+= byteArrayToHex(DES(orRes,keyArr)).substring(0, 16);
        
        return crypt;
        
        
    }
    
        
    /*************************************************************************
     * 
     *                               OFB 
     *
     *************************************************************************/
    public static String OFB(String message, String key, String IV, int k){
        String cryptString=""; //String that all crypt will be concatted to
        byte[] iVec = new byte[8]; //Will hold IV
        byte[] DESout = new byte[8];
        byte[] keyArr = new byte[8];
        int newLen=message.length(); //length if no padding is needed
        int blockLen = k/4;
        if(message.length()%blockLen !=0) //check if padding is needed
            newLen = message.length() + blockLen - message.length()%blockLen;
        char[] charArr = new char[newLen];
        
        int j=0;
        for (j=0;j<message.length();j++) //give padding
            charArr[j]=message.charAt(j);//Copy over to Char Array
        for(;j<newLen;j++)
            charArr[j]='0';              //apply 0 to padding

        keyArr = stringToByte(key,16);
        iVec = stringToByte(IV,16);
        
        for(int i=0;i<(newLen/blockLen);i++){
                                //START THE ENCRYPTION
            DESout = DES(iVec,keyArr); 
                                //RUN IV AND KEY THROUGH DES
            String temp = byteArrayToHex(DESout); //Put DESout back to a string
            String ivString = byteArrayToHex(iVec); //Put Vec to an string 
            //This is needed so I can operate on it 1 char at a time which i cant
            //do in a byte array, because i cant access lower and upper byte
            String t2 = "";
            for(int b=0;b<blockLen;b++){ //Copy the needed k/4 hex values
                t2+=temp.charAt(b); //the rest will be thrown away
            }
                       //XOR 1 HEX VALUE AT A TIME OF MESSAGE AND DES OUTPUT
            for(int b=0;b<blockLen;b++){//xor with plaintext to get output
                byte or1 =(byte)(Integer.parseInt(String.valueOf(charArr[i*blockLen+b]), 16));
                byte or2 = (byte)Integer.parseInt(String.valueOf(t2.charAt(b)),16);
                cryptString+=Integer.toHexString(or1^or2); //ad newly XORd val onto final str
            }
                      //CREATE NEW IV BY SHIFTING OLD ONE AND APPENDING t2
            String newIV = "";
            int z;
            for(z=0;z<(ivString.length())-(k/4);z++){
                newIV+=ivString.charAt(z+(k/4));
            }//Shifts over bits from previous IV to new IV
            for(int b=0;z<ivString.length();z++){
                newIV+=t2.charAt(b);
                b++;
            }//Adds the final bits from K bit output of DES
            for(int b=0; b<16;b+=2){ //Create new IV for next iteration
                iVec[b/2] = (byte)(Integer.parseInt(String.valueOf(newIV.charAt(b)), 16)*16);
                iVec[b/2]+=(byte)(Integer.parseInt(String.valueOf(newIV.charAt(b+1)), 16));
            }
        }
        
        return cryptString.substring(0, message.length());
    }
        
    /*************************************************************************
     * 
     *                               CFB 
     *
     *************************************************************************/
    public static String CFB(String message, String key, String IV, int k){
        String cryptString="";      //String will contain crypt text
        byte[] iVec = new byte[8];  //Will hold IV
        byte[] DESout = new byte[8];//Hold output of DES
        byte[] keyArr = new byte[8];//holds byte[] of key for DES
        int newLen=message.length();//Length of message if there is no padding
        int blockLen = k/4;
        if(message.length()%blockLen !=0) //Calculate padding if it needs
            newLen = message.length() + blockLen - message.length()%blockLen;
        char[] charArr = new char[newLen]; //Apply padding len
        
        int j=0;
        for (j=0;j<message.length();j++) //give padding
            charArr[j]=message.charAt(j);//Copy over to Char Array
        for(;j<newLen;j++)
            charArr[j]='0';              //apply 0 to padding

        keyArr = stringToByte(key,16); //fill key Arr
        iVec = stringToByte(IV,16);    //fill IV Arr
        
        for(int i=0;i<(newLen/blockLen);i++){
                                //START THE ENCRYPTION
            DESout = DES(iVec,keyArr); 
                                //RUN IV AND KEY THROUGH DES
            String temp = byteArrayToHex(DESout); //Put DESout back to a string
            String ivString = byteArrayToHex(iVec); //Put Vec to an string 
            //This is needed so I can operate on it 1 char at a time which i cant
            //do in a byte array, because i cant access lower and upper byte
            String t2 = "";
            for(int b=0;b<blockLen;b++){ //Copy the needed k/4 hex values
                t2+=temp.charAt(b); //the rest will be thrown away
            }
                       //XOR 1 HEX VALUE AT A TIME OF MESSAGE AND DES OUTPUT
            String tfinal = "";
            for(int b=0;b<blockLen;b++){//xor with plaintext to get output
                byte or1 =(byte)(Integer.parseInt(String.valueOf(charArr[i*blockLen+b]), 16));
                byte or2 = (byte)Integer.parseInt(String.valueOf(t2.charAt(b)),16);
                tfinal+=Integer.toHexString(or1^or2); //ad newly XORd val onto temp
            } //temp is needed to create new IV
            cryptString+=tfinal; //add temp onto final
                 //CREATE NEW IV BY SHIFTING OLD ONE AND APPENDING K BIT CIPHER
            String newIV = "";
            int z;
            for(z=0;z<(ivString.length())-(k/4);z++){
                newIV+=ivString.charAt(z+(k/4));
            }//Shifts over bits from previous IV to new IV
            for(int b=0;z<ivString.length();z++){
                newIV+=tfinal.charAt(b);
                b++;
            }//Adds the final bits from last cipherblock k bit
            for(int b=0; b<16;b+=2){ //Create new IV for next iteration
                iVec[b/2] = (byte)(Integer.parseInt(String.valueOf(newIV.charAt(b)), 16)*16);
                iVec[b/2]+=(byte)(Integer.parseInt(String.valueOf(newIV.charAt(b+1)), 16));
            }
        }
        
        return cryptString.substring(0, message.length());
    }

    public static byte[] DES(byte[] text, byte[] key){
        try{
            DESKeySpec dks = new DESKeySpec(key);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey DESkey = skf.generateSecret(dks);
            Cipher cipher = Cipher.getInstance("DES");
            
            cipher.init(Cipher.ENCRYPT_MODE, DESkey);
            
            byte[] crypt = cipher.doFinal(text);
            
            return crypt;
            
        }catch(Exception e){
            return null;
        }
    }    
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
    //Takes string of Hex values, parses int from each char, then stores in byte[]
    public static byte[] stringToByte(String m, int len){
        byte[] a = new byte[len/2];
        for(int i=0; i<len;i+=2){
            a[i/2] = (byte)(Integer.parseInt(String.valueOf(m.charAt(i)), 16)*16);
            a[i/2]+=(byte)(Integer.parseInt(String.valueOf(m.charAt(i+1)), 16));
        }
        return a;
    }
}