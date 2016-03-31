package givtech.ebdcrypto;

import android.util.Log;

/**
 * Created by jooney on 3/26/16.
 */
public class GenerateCertCSR {
    static {
        System.loadLibrary("EBDCrypto_JNI_android");
    }

    private native byte[] nativeGenPubCSR(byte[] username, int username_offset, int username_len,
                                      byte[] socialnum, int socialnum_offset, int socialnum_len,
                                      byte[] phonenum, int phonenum_offset, int phonenum_len,
                                      byte[] UsimID, int UsimID_offset, int UsimID_len,
                                      byte[] UserID, int UserID_offset, int UserID_len,
                                      byte[] Algorithm, int Algorithm_offset, int Algorithm_len,
                                      byte[] Pubkey_Qx, int Pubkey_Qx_offset, int Pubkey_Qx_len,
                                      byte[] Pubkey_Qy, int Pubkey_Qy_offset, int Pubkey_Qy_len);
    public GenerateCertCSR()
    {

    }

    public byte[] generateCertCSR(byte[] username, int username_offset, int username_len,
                                  byte[] socialnum, int socialnum_offset, int socialnum_len,
                                  byte[] phonenum, int phonenum_offset, int phonenum_len,
                                  byte[] UsimID, int UsimID_offset, int UsimID_len,
                                  byte[] UserID, int UserID_offset, int UserID_len,
                                  byte[] Algorithm, int Algorithm_offset, int Algorithm_len,
                                  byte[] Pubkey_Qx, int Pubkey_Qx_offset, int Pubkey_Qx_len,
                                  byte[] Pubkey_Qy, int Pubkey_Qy_offset, int Pubkey_Qy_len)
    {
        byte[] NULL = {'\0', };
        if ( (username == null) || (socialnum == null) || (phonenum == null) || (UsimID == null) || (UserID == null) | (Algorithm == null) || (Pubkey_Qx == null) || (Pubkey_Qy == null) ||
                (username_offset < 0) || (phonenum_offset < 0) || (UsimID_offset < 0) || (UserID_offset < 0) || (Algorithm_offset < 0) || (Pubkey_Qx_offset < 0) || (Pubkey_Qy_offset < 0) ||
                (username_len < 0) || (socialnum_len < 0) || (phonenum_len < 0) || (UsimID_len < 0) || (UserID_len < 0) || (Algorithm_len < 0) || (Pubkey_Qx_len < 0) || (Pubkey_Qy_len < 0) ||
                ((username_offset + username_len) > username.length) || ((socialnum_offset + socialnum_len) > socialnum.length) || ((phonenum_offset + phonenum_len) > phonenum.length) ||
                ((UsimID_offset + UsimID_len) > UsimID.length) || ((UserID_offset + UserID_len) > UserID.length) || ((Algorithm_offset + Algorithm_len) > Algorithm.length) ||
                ((Pubkey_Qx_offset + Pubkey_Qx_len) > Pubkey_Qx.length) || ((Pubkey_Qy_offset + Pubkey_Qy_len) > Pubkey_Qy.length) ) {
            Log.e("Error", "Generate Cert CSR Input Error!");
        } else {
            return nativeGenPubCSR(username, username_offset, username_len, socialnum, socialnum_offset, socialnum_len,
                    phonenum, phonenum_offset, phonenum_len, UsimID, UsimID_offset, UsimID_len, UserID, UserID_offset, UserID_len,
                    Algorithm, Algorithm_offset, Algorithm_len, Pubkey_Qx, Pubkey_Qx_offset, Pubkey_Qx_len, Pubkey_Qy, Pubkey_Qy_offset, Pubkey_Qy_len);
        }
        return NULL;
    }
}
