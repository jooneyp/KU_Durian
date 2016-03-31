package ebdcrypto;

public class BytesUtils {

	public static int bytesToint(byte[] value)
	{
		return ((value[0]<<8) + value[1]);  
	}

	public static int bytesToint(byte[] bytes, int off, int len)
	{
		int result = 0;
	  
		for (int i=0; i<len; i++)
		{
				result <<= 8;
				result |= (bytes[(off+i)] < 0) ? (bytes[(off+i)]+256) : bytes[(off+i)];
		}
	  
		return result;
	}

	public static int bytesToInt(byte[] bytes)
	{
		return bytesToInt(bytes, 0, 4);
	}

	
	 public static int bytesToInt(byte[] bytes, int off, int len)
	 {
	  int result = 0;
	  
	  for (int i=0; i<len; i++)
	  {
	   result <<= 8;
	   result |= (bytes[(off+i)] < 0) ? (bytes[(off+i)]+256) : bytes[(off+i)];
	  }
	  
	  return result;
	 }

	public static int charToInt(byte c, int radix) {
		int i;
		if (c >= 48 && c <= 57)
			i = c - 48;
		else if (c >= 65 && c <= 90)
			i = c - 65 + 10;
		else if (c >= 97 && c <= 122)
			i = c - 97 + 10;
		else
			i = -1;
		if (i < 0 || i >= radix)
			return -1;
		else
			return i;
	}

	public static boolean compareByteArray(byte[] a, byte[] b) {
		
		if (a.length != b.length)
			return false;
		for (int i = 0; i < a.length; i++)
			if (a[i] != b[i])
				return false;
		return true;
	}
	
	public static boolean compareByteArray(byte[] a, byte[] b, int len) {	
		for (int i = 0; i < len; i++)
			if (a[i] != b[i])
				return false;
		return true;
	}
	
	public static byte[] cloneByteArray(byte[] a) {
		
		byte[] result = new byte[a.length];
		
		System.arraycopy(a, 0, result, 0, a.length);
		
		return result;
	}

	public static byte[] cropByteArray(byte[] target, int offset, int length){
		byte[] result = new byte[length];
		System.arraycopy(target, offset, result, 0, (length));		
		return result;
	}
	
	public static byte[] ejectByteArray(byte[] target, int offset, int length){
		byte[] result = new byte[target.length-length];			
		System.arraycopy(target, 0, result, 0, (offset));		
		System.arraycopy(target, (offset+length), result, (offset), (target.length-offset-length));
		return result;
	}
	
	public static void setBytes(byte[] target, byte b,int off, int length)
	{
		for (int i = off; i < off + length; i++)
			target[i] = b;
	}
	
	public static byte[] insertBytes(byte[] target, int offset,
			int targetLength, byte[] insertion, int insertionLength) {
		byte result[] = new byte[(targetLength + insertionLength)];
		System.arraycopy(target, 0, result,  0,  offset);
		System.arraycopy(insertion,  0, result,  offset,insertionLength);
		System.arraycopy(target, offset, result, (insertionLength + offset),(targetLength - offset));
		return result;
	}
	
	public static byte[] insertSingleByte(byte[] target, int offset,
			int targetLength, byte insertion) {
		byte[] insertion_ = new byte[1];
		insertion_[0] = insertion;
		return insertBytes(target, offset, targetLength, insertion_, 1);
	}
	 
	public static byte[] intToByte(int value) {
		return new byte[] { (byte) (value >>> 8), (byte) (value & 0xff) };
	}	

	public static byte[] intToBytes(int value) {
		return new byte[] { (byte) (value >>> 24), (byte) (value >> 16 & 0xff),
				(byte) (value >> 8 & 0xff), (byte) (value & 0xff) };
	}
	
	public static void intToBytes(int value, byte[] bytes, int off) {
		bytes[(off)] = (byte) (value >>> 24);
		bytes[(off+1)] = (byte) (value >> 16 & 0xff);
		bytes[(off+2)] = (byte) (value >> 8 & 0xff);
		bytes[(off+3)] = (byte) (value & 0xff);
	}	
	
	public static byte[] intToBytesV(int number)
	{
		if ((number & 0xFF000000) != 0) return new byte[] { (byte) (number >>> 24), (byte) (number >> 16 & 0xff),
			(byte) (number >> 8 & 0xff), (byte) (number & 0xff) };
		else if ((number & 0x00FF0000) != 0) return new byte[] { (byte) (number >> 16 & 0xff),
			(byte) (number >> 8 & 0xff), (byte) (number & 0xff) };
		else if ((number & 0x0000FF00) != 0) return new byte[] { 
			(byte) (number >> 8 & 0xff), (byte) (number & 0xff) };
		else 
			return new byte[] {(byte)number};
	}
	
	public static void longToBytes(long value, byte[] bytes, int off) {
		bytes[(off)] = (byte) (value >>> 56);
		bytes[(off+1)] = (byte) (value >> 48 & 0xff);
		bytes[(off+2)] = (byte) (value >> 40 & 0xff);
		bytes[(off+3)] = (byte) (value >> 32 & 0xff);
		bytes[(off+4)] = (byte) (value >> 24 & 0xff);
		bytes[(off+5)] = (byte) (value >> 16 & 0xff);
		bytes[(off+6)] = (byte) (value >> 8 & 0xff);
		bytes[(off+7)] = (byte) (value & 0xff);
	}
	
	public static byte[] resizeArray(byte[] source, int len) {
		byte[] target = new byte[len];
		len = (source.length < len) ? source.length : len;
		System.arraycopy(source, 0, target, 0, len);
		return target;
	}

	public static byte[] trimByteArray(byte[] target, int length) {
	
		byte result[] = new byte[(length)];	
		System.arraycopy(target, 0, result, 0, length);
		return result;
	}
	
	public static byte[] concatByteArray(byte[] a, byte[] b) {
		byte target[] = new byte[(short)(a.length + b.length)];
		System.arraycopy(a, 0, target, 0, a.length);
		System.arraycopy(b, 0, target, a.length, b.length);
		return target;
	}

	public static String toString(byte b)
	{
		StringBuffer sb = new StringBuffer(2);
		int i = (b & 0xF0) >> 4;
		int j = b & 0x0F;
		sb.append(new Character((char)((i > 9) ? (65 + i - 10) : (48 + i))));
		sb.append(new Character((char)((j > 9) ? (65 + j - 10) : (48 + j))));
		
		return sb.toString();
	}	 

	public static String HextoString(byte[] byteArray)
	{
		if(byteArray==null)
			return "NULL";
		return HextoString(byteArray, 0, byteArray.length);
	}
	
	public static String HextoString(byte[] byteArray, int off, int len)
	{
		//if (byteArray.length < off + len)
		//	len = byteArray.length - off;
		StringBuffer sb = new StringBuffer(2 * len);
		for (int i = 0; i < len; i++) {
			sb.append(toString(byteArray[off + i]));
		}
		
		return sb.toString();
	}
	
	public static String HextoStringwithcol(byte[] byteArray, int off, int len)
	{
		if (byteArray.length < off + len)
			len = byteArray.length - off;
		StringBuffer sb = new StringBuffer(2 * len);
		boolean flag = true;
		for (int i = 0; i < len; i++) {
			
			if (flag)
				flag = false;
			else
				sb.append(":");
			sb.append(toString(byteArray[off + i]));
		}
		
		return sb.toString();
	}
	
	public static byte[] HexstringToHex(String str)
	{
		byte[] buffer = new byte[str.length()/2];
		
		for(int i=0;i<buffer.length;i++)
		{
			buffer[i] = (byte)Integer.parseInt(str.substring(2*i, (2*i)+2), 16);
		}
	
		return buffer;
	}
}
