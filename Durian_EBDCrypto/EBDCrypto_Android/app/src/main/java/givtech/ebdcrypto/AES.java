package givtech.ebdcrypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class AES {
	
	static {
		System.loadLibrary("EBDCrypto_JNI_android");
	}
	
	public static final int AES_BLOCK_SIZE = 16;
	
	public static final int AES128 = 16;
	public static final int AES192 = 24;
	public static final int AES256 = 32;
	
	public static final int ENCRYPT = 1;
	public static final int DECRYPT = 0;
	
	private native int nativeAESCBC(int enc, byte[] user_key, int key_offset, int key_len_in_bytes, byte[] iv, int iv_offset, byte[] input, int input_offset, int len, byte[] out, int output_offset);
	
	public AES() {
		
	}
	
	public int getOutputSize(int enc, int inputLen) {
		int outputLen = 0, padLen;
		
		if(enc == ENCRYPT) {
			padLen = AES_BLOCK_SIZE - inputLen % AES_BLOCK_SIZE;
			if(padLen == AES_BLOCK_SIZE) {
				outputLen = inputLen + AES_BLOCK_SIZE;
			} else {
				outputLen = inputLen + padLen;
			}
		} else {
			outputLen = inputLen;
		}
		
		return outputLen ;
	}
	
	public int CBCMode(int enc, byte[] user_key, int key_offset, int key_len_in_bytes, byte[] iv, int iv_offset, byte[] input, int input_offset, int input_len, byte[] output, int output_offset)
	{
		if( (user_key == null) || (iv == null) || (input == null) || (output == null) ||
			((key_len_in_bytes != AES128) && (key_len_in_bytes != AES192) && (key_len_in_bytes != AES256)) ||
			(key_offset < 0) || (iv_offset < 0) || (input_offset < 0) || (output_offset < 0) || (input_len < 0) ||
			((key_offset + key_len_in_bytes) > user_key.length) || ((iv_offset + 16) > iv.length) || ((input_offset + input_len) > input.length) )
			return -1;
		
		int expectedoutlen = getOutputSize(enc, input_len);
		if((output_offset + expectedoutlen) > output.length)
			return -1;
		
		return nativeAESCBC(enc, user_key, key_offset, key_len_in_bytes, iv, iv_offset, input, input_offset, input_len, output, output_offset);
	}
}
