#include <stdio.h>
#include <string.h>
#include <gcrypt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#include "cgic/cgic.h"
#include "base64.h"

#define KEY_DIR "key"
#define PUB_KEY "key/pub.key"
#define SALT "salt.txt"
#define DATA "key/data.txt"

#define equals(X, Y) (strcmp(X, Y) == 0)

char *itoa(int value) {
  
  char *buffer = (char *) malloc(10);
  snprintf(buffer, 10, "%d", value);  
  return buffer;
} 

int directoryExists(char *dirName) {

  struct stat s;
  if (stat(dirName, &s) == 0 && S_ISDIR(s.st_mode))
    return 1;
  else
    return 0;
}

int fileExists(char *fileName) {
  
  if (access(fileName, F_OK) == -1)
    return 0;
  else
    return 1;
}

char *receiveCgi(char *keyName) {

  int length;
  cgiFormStringSpaceNeeded(keyName, &length);
  char *retBuffer = (char *)calloc(1, length);
  if (cgiFormString(keyName, retBuffer, length) != cgiFormSuccess) {
    free(retBuffer);
    return NULL;
  }
  return retBuffer;
}

int commandIs(const char *command) {
  
  char *cmd = receiveCgi("cmd");
  int isEqual = equals(cmd, command);
  free(cmd);
  return isEqual;
}

void debug(char *message) {

  fprintf(cgiOut, "%s", message);
  fprintf(cgiOut, "\n" );
}

int saveFile(char *fileName, char *data) {
  
  FILE *fileHandle  = fopen(fileName, "w+");
  if (fileHandle == NULL)
    return 0;
  fprintf(fileHandle, "%s", data);
  fclose(fileHandle);
  return 1;
}

char *loadFile(char *fileName) {

  char *buffer = NULL;
  FILE *file = fopen(fileName, "r");
  if (file != NULL) {
    if (fseek(file, 0L, SEEK_END) == 0) {
      long bufferSize = ftell(file);
      if (bufferSize == -1) {
	fclose(file);
        return NULL;
      }
      buffer = calloc(1, bufferSize + 1);
      if (fseek(file, 0L, SEEK_SET) != 0) {
        free(buffer);
	fclose(file);
        return NULL;
      }
      fread(buffer, 1, bufferSize, file);
      if (ferror(file) != 0) {
        free(buffer);
	fclose(file);
        return NULL;
      }
    }
    fclose(file);
  }
  return buffer;
}

char *calcHashBinary(char *data, int dataLen) {

  gcry_md_hd_t md;
  if (gcry_md_open(&md, GCRY_MD_TIGER, 0))
    return NULL;

  gcry_md_write(md, data, dataLen);
  int mdSize = gcry_md_get_algo_dlen(GCRY_MD_TIGER);
  if (mdSize == 0)
    return NULL;
  
  char *hash;
  hash = (char *)gcry_md_read(md, GCRY_MD_TIGER);
  char *hash64 = (char *)calloc(1, base64_enc_len(mdSize)+1);
  base64_encode(hash64, hash, mdSize);
  
  gcry_md_close(md);
  return hash64; 
}

// return value needs to be free()d
char *sexpToBinary(gcry_sexp_t sexp, int *length) {

    *length = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
    char *sexpBuf = (char *)calloc(1, *length);
    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, sexpBuf, *length);
    return sexpBuf;
}

// return value needs to be free()d
char *base64ToBinary(char *data64, int *length) {
  
  int data64Len = strlen(data64);
  *length = base64_dec_len(data64, data64Len);
  char *data = calloc(1, (*length)+1);
  base64_decode(data, data64, data64Len);
  return data;
}

// for null terminated strings. use calcHashBinary() for binary.
char *calcHash(char *data) {

  int dataLen = strlen(data);
  if (dataLen == 0)
    return NULL;

  return calcHashBinary(data, dataLen);
}

char *genSalt() {
  char *saltBinary = calloc(1, 512+1);
  char *salt64 = calloc(1, base64_enc_len(512)+1);
  gcry_create_nonce(saltBinary, 512);
  base64_encode(salt64, saltBinary, 512);
  free(saltBinary);
  return salt64;
}

gcry_sexp_t binaryToSexp(char *binaryData, int binaryDataLen) {

  gcry_sexp_t sexp;
  
  if (gcry_sexp_new(&sexp, binaryData, binaryDataLen, 0))
    return NULL;
  else
    return sexp;
}

gcry_sexp_t hashToSexp(char *base64Hash) {

  gcry_mpi_t mpiHash;
  if (gcry_mpi_scan(&mpiHash, GCRYMPI_FMT_USG, base64Hash, strlen(base64Hash), NULL))
    return NULL;

  gcry_sexp_t sexpHash;
  if (gcry_sexp_build(&sexpHash, NULL, "(data (flags raw) (value %m))", mpiHash))
    return NULL;
  else
    return sexpHash;
}

int validateHash(char *base64Data, char *base64RemoteHash) {

  char *base64LocalSalt = loadFile(SALT);
  int base64LocalSaltLen = strlen(base64LocalSalt);
  int base64DataLen = strlen(base64Data);
  int base64DataAndLocalSaltLen = base64DataLen + base64LocalSaltLen;
  char *base64DataAndLocalSalt = calloc(1, base64DataAndLocalSaltLen+1);
  strcpy(base64DataAndLocalSalt, base64Data);
  strcat(base64DataAndLocalSalt, base64LocalSalt);
  char *base64LocalHash = calcHashBinary(base64DataAndLocalSalt, base64DataAndLocalSaltLen);

  int equal = equals(base64LocalHash, base64RemoteHash);
    
  free(base64LocalSalt);
  free(base64DataAndLocalSalt);
  free(base64LocalHash);
  if (equal)    
    return 1;
  else
    return 0;
}

int validateSignature(char *base64Sig, char *base64Hash, char *base64PubKey) {

  int binarySigLen;
  char *binarySig = base64ToBinary(base64Sig, &binarySigLen);
  gcry_sexp_t sexpSig = binaryToSexp(binarySig, binarySigLen);
  if (sexpSig == NULL) {
    free(binarySig);
    return 0;
  }
  int binaryPubKeyLen;
  char *binaryPubKey = base64ToBinary(base64PubKey, &binaryPubKeyLen);
  gcry_sexp_t sexpPubKey = binaryToSexp(binaryPubKey, binaryPubKeyLen);
  if (sexpPubKey == NULL) {
    gcry_sexp_release(sexpSig);
    free(binarySig);
    free(binaryPubKey);    
    return 0;
  }
  gcry_sexp_t sexpHash = hashToSexp(base64Hash);
  if (sexpHash == NULL) {
    gcry_sexp_release(sexpSig);
    gcry_sexp_release(sexpPubKey);
    free(binarySig);
    free(binaryPubKey);
    return 0;
  }

  int err = gcry_pk_verify(sexpSig, sexpHash, sexpPubKey);
  gcry_sexp_release(sexpSig);
  gcry_sexp_release(sexpHash);
  gcry_sexp_release(sexpPubKey);
  free(binarySig);

  if (err) 
    return 0;
  else
    return 1;
}

// requires dataHash=<hash>, data=<data>
void unitTest_validateHash_ValidatesTheHashOfSaltedData() {

  char *dataHash = receiveCgi("dataHash");
  char *data = receiveCgi("data");

  if (validateHash(data, dataHash))
    debug("PASS unitTest_validateHash_ValidatesTheHashOfSaltedData()");
  else
    debug("FAIL unitTest_validateHash_ValidatesTheHashOfSaltedData()");
    
  free(data);
  free(dataHash);
}

// requires dataHash=<hash> sig=<hash signature>
void unitTest_validateSignature_DoesNotValidateAnImproperlySignedHash() {

  char *dataHash = receiveCgi("dataHash");
  dataHash[0] = 'q'; // break it for the test.
  char *sig = receiveCgi("sig");
  char *key = loadFile(PUB_KEY);

  if (validateSignature(sig, dataHash, key))
    debug("FAIL unitTest_validateSignature_DoesNotValidateAnImproperlySignedHash()");
  else
    debug("PASS unitTest_validateSignature_DoesNotValidateAnImproperlySignedHash()");
}


// requires dataHash=<hash> sig=<hash signature>
void unitTest_validateSignature_ValidatesAProperlySignedHash() {

  char *dataHash = receiveCgi("dataHash");
  char *sig = receiveCgi("sig");
  char *key = loadFile(PUB_KEY);

  if (validateSignature(sig, dataHash, key))
    debug("PASS unitTest_validateSignature_ValidatesAProperlySignedHash()");
  else
    debug("FAIL unitTest_validateSignature_ValidatesAProperlySignedHash()");
}

// requires test1=hello world!
void unitTest_receiveCgi_receivesExactlyTheValueSent() {

  char *test = receiveCgi("test1");
  if (strlen(test) != 12 || test[0] != 'h' || test[11] != '!' || test[12] != 0x0)
    debug("FAIL unitTest_receiveCgi_receivesExactlyTheValueSent()");
  else
    debug("PASS unitTest_receiveCgi_receivesExactlyTheValueSent()");
  free(test);
}

// requires test1=hello world!
void unitTest_saveFile_savesExactlyTheStringPassedToIt() {

  remove("test.txt");
  char *test = receiveCgi("test1");
  saveFile("test.txt", test);
  char *test2 = loadFile("test.txt");
  if (strlen(test2) != 12 || test2[0] != 'h' || test2[11] != '!' || test2[12] != 0x0)
    debug("FAIL unitTest_saveFile_savesExactlyTheStringPassedToIt()");
  else
    debug("PASS unitTest_saveFile_savesExactlyTheStringPassedToIt()");
  free(test);
  free(test2);
  remove("test.txt");
}

// requires test1=hello world!, test1Hash=<hash of test1>
void unitTest_calcHash_createsTheSameHashThatTheClientDoes() {

  char *test1 = receiveCgi("test1");
  char *test1Hash = receiveCgi("test1Hash");
  char *serverTest1Hash = calcHash(test1);
  
  if (equals(test1Hash, serverTest1Hash))
    debug("PASS unitTest_calcHash_createsTheSameHashThatTheClientDoes()");
  else
    debug("FAIL unitTest_calcHash_createsTheSameHashThatTheClientDoes()");
  
  free(test1);
  free(test1Hash);
  free(serverTest1Hash);
}

// requires key to exist on server, requires keyHash=<hash of key>
void unitTest_loadFile_loadsTheSamePublicKeyAsTheClientHas() {

  char *localKey = loadFile(PUB_KEY);
  char *localKeyHash = calcHash(localKey);
  char *remoteKeyHash = receiveCgi("keyHash");
  if (equals(localKeyHash, remoteKeyHash))
    debug("PASS unitTest_loadFile_loadsTheSamePublicKeyAsTheClientHas()");
  else
    debug("FAIL unitTest_loadFile_loadsTheSamePublicKeyAsTheClientHas()");

  free(localKey);
  free(localKeyHash);
  free(remoteKeyHash);
}

// requires salt.txt to exist on server, requires saltHash=<hash of salt>                   
void unitTest_loadFile_loadsTheSameSaltAsTheClientHas() {

  char *localSalt = loadFile(SALT);
  char *localSaltHash = calcHash(localSalt);
  char *remoteSaltHash = receiveCgi("saltHash");

  if (equals(localSaltHash, remoteSaltHash))
    debug("PASS unitTest_loadFile_loadsTheSameSaltAsTheClientHas()");
  else
    debug("FAIL unitTest_loadFile_loadsTheSameSaltAsTheClientHas()");

  free(localSalt);
  free(localSaltHash);
  free(remoteSaltHash);
}

// requires binaryKeyHash=<hash>
void unitTest_base64ToBinary_serversBinaryKeyMatchesClientsBinaryKey() {

  char *localBase64Key = loadFile(PUB_KEY);
  int localBinaryKeyLen;
  char *localBinaryKey = base64ToBinary(localBase64Key, &localBinaryKeyLen);
  char *localBinaryKeyHash = calcHashBinary(localBinaryKey, localBinaryKeyLen);
  char *remoteBinaryKeyHash = receiveCgi("binaryKeyHash");

  if (equals(localBinaryKeyHash, remoteBinaryKeyHash))
    debug("PASS unitTest_base64ToBinary_serversBinaryKeyMatchesClientsBinaryKey()");
  else
    debug("FAIL unitTest_base64ToBinary_serversBinaryKeyMatchesClientsBinaryKey()");

  
  free(localBase64Key);
  free(localBinaryKey);
  free(localBinaryKeyHash);
  free(remoteBinaryKeyHash);
}

void unitTests() {

  // require test1=hello world!
  unitTest_receiveCgi_receivesExactlyTheValueSent();
  unitTest_saveFile_savesExactlyTheStringPassedToIt();

  // requires test1=hello world!, test1Hash=<hash of test1>
  unitTest_calcHash_createsTheSameHashThatTheClientDoes();

  // requires key to exist on server, requires keyHash=<hash of key>
  unitTest_loadFile_loadsTheSamePublicKeyAsTheClientHas();

  // requires salt.txt to exist on server, requires saltHash=<hash of salt>
  unitTest_loadFile_loadsTheSameSaltAsTheClientHas();

  // requires binaryKeyHash=<hash>
  unitTest_base64ToBinary_serversBinaryKeyMatchesClientsBinaryKey();

  // requires dataHash=<hash> sig=<hash signature>
  unitTest_validateSignature_ValidatesAProperlySignedHash();

  // requires dataHash=<hash> sig=<hash signature>
  unitTest_validateSignature_DoesNotValidateAnImproperlySignedHash();

  // requires dataHash=<hash>, data=<data>
  unitTest_validateHash_ValidatesTheHashOfSaltedData();

}

int genSaltAndSaveToDisk() {
  
  char *salt = genSalt();
  int err = saveFile(SALT, salt);
  free(salt);
  return err;
}

int cgiMain() {

  cgiHeaderContentType("text/html");
  if (!directoryExists(KEY_DIR))
    mkdir(KEY_DIR, 0700);

  if (!fileExists(PUB_KEY)) {
    char *pubKey = receiveCgi("key");
    if (pubKey != NULL) {
      saveFile(PUB_KEY, pubKey);
      free(pubKey);
      debug("keyreceived");
    } else {
      debug("nokey");
    }
    return 0;
  }
  
  if (!fileExists(SALT))
    genSaltAndSaveToDisk();

  if (commandIs("salt")) {
    char *salt = loadFile(SALT);
    fprintf(cgiOut, "salt:");
    fprintf(cgiOut, "%s", salt);
    fprintf(cgiOut, "\n");
    free(salt);
    return 0;
  }

  if (commandIs("unitTests")) {
    unitTests();
    return 0;
  }

  if (commandIs("put")) {
    char *dataHash = receiveCgi("dataHash");
    char *sig = receiveCgi("sig");
    char *data = receiveCgi("data");
    char *localKey = loadFile(PUB_KEY);
    if (validateHash(data, dataHash)) {
      if (validateSignature(sig, dataHash, localKey)) {
	if(saveFile(DATA, data))
	  debug("saved");
      }
    }
    genSaltAndSaveToDisk();
    free(dataHash);
    free(sig);
    free(data);
    free(localKey);
    return 0;
  }

  if (commandIs("get")) {
    if (!fileExists(DATA)) {
      fprintf(cgiOut, "nodata\n");
      return 0;
    }
    char *sig = receiveCgi("sig");
    char *localKey = loadFile(PUB_KEY);
    char *data;
    char *salt = loadFile(SALT);
    char *saltHash = calcHash(salt);
    if (validateSignature(sig, saltHash, localKey)) {
      
      if (!fileExists(DATA)) {
	fprintf(cgiOut, "nodata\n");
	genSaltAndSaveToDisk();
	return 0;
      } else {
	data = loadFile(DATA);
	fprintf(cgiOut, "data:%s\n", data);
      }
    } else {
      fprintf(cgiOut, "getfail\n");
    }
    genSaltAndSaveToDisk();
    free(sig);
    free(data);
    free(salt);
    free(saltHash);
    return 0;
  }
  return 0;
}
