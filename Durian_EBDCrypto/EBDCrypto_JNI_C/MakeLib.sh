gcc -fPIC -c BN.c GFP.c GFP_EC.c aes.c ecdsa.c hash_drbg.c NativeC.c ca.c entropy.c sha2.c DBConnector.c -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/System/Library/Frameworks/JavaVM.framework/Versions/A/Headers -I/usr/local/Cellar/mysql/5.7.11/include/mysql -w

# MODIFY lib[LIBNAME].so/dll/dylib
gcc -shared -o libEBDCrypto_JNI_android.dylib *.o -lz -lm -lmysqlclient -L/usr/local/Cellar/mysql/5.7.11/lib
rm *.o

# NEED JAVA / MYSQL
# COMPILE OPTIONS
# gcc -fPIC -I$(JAVA_HEADERS) -I$(MYSQL_HEADERS)
# LINKER OPTIONS
# gcc -shared -lz -lm -lmysqlclient -L$(MYSQL_LIB_FOLDER)