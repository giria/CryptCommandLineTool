#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <CommonCrypto/CommonCryptor.h>

char cryptKey[kCCKeySizeAES256] = "O3fX{j{{*1:r[S[rTOYBbz)+mDIc}off";

int main (int argc, char * argv[])
{
    CCOperation cryptoOp = kCCEncrypt;
    char *key = NULL;
    char *inFile = NULL;
    char *outFile = NULL;
    int c;
    
    // Process options
    while ((c = getopt (argc, argv, "edk:i:o:")) != -1)
        switch (c)
    {
        case 'e':
            cryptoOp = kCCEncrypt;
            break;
        case 'd':
            cryptoOp = kCCDecrypt;
            break;
        case 'k':
            key = optarg;
            break;
        case 'i':
            inFile = optarg;
            break;
        case 'o':
            outFile = optarg;
            break;
        case '?':
            if (strchr("kio", optopt))
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            abort ();
    }
    
    if (!inFile || !outFile)
    {
        printf("Usage: %s [-e] [-d] -k <keyfile> -i <infile> -o <outfile>\n", argv[0]);
        exit(1);
    }

    // Set key if specified
    if (key)
    {
        if (strlen(key) != kCCKeySizeAES256)
        {
            printf("%s: Key must be %d bytes\n", argv[0], kCCKeySizeAES256);
            exit(1);  
        }
        strncpy(cryptKey, key, kCCKeySizeAES256);
    }
    
    // Open input and output files
    FILE *fin = fopen(inFile, "rb");
    FILE *fout = fopen(outFile, "wb");

    if(!fin)
    {
        printf("%s: Can't open input file\n", argv[0]);
        exit(1);
    }
    
    if(!fout)
    {
        printf("%s: Can't open output file\n", argv[0]);
        exit(1);
    }
    
    // Set up cryptor
    CCCryptorRef cryptoRef;
    CCCryptorCreate(cryptoOp, kCCAlgorithmAES128, kCCOptionPKCS7Padding, cryptKey, kCCKeySizeAES256, NULL, &cryptoRef);
    void *inBuffer = malloc(kCCBlockSizeAES128);
    void *outBuffer = malloc(kCCBlockSizeAES128);
    size_t numBytes;
    
    // Encrypt/decrypt
    while (!feof(fin))
    {
        numBytes = fread(inBuffer, sizeof(char), kCCBlockSizeAES128, fin);
        
        if (kCCSuccess != CCCryptorUpdate(cryptoRef, inBuffer, numBytes, outBuffer, kCCBlockSizeAES128, &numBytes))
        {
            printf("%s: Crypto error processing file\n", argv[0]);
        }
        
        if (fwrite(outBuffer, sizeof(char), numBytes, fout) != numBytes)
        {
            printf("%s: Error writing output file\n", argv[0]);
            exit(1);
        }
    }
    
    // Flush cryptor
    CCCryptorFinal(cryptoRef, outBuffer, kCCBlockSizeAES128, &numBytes);
    if (fwrite(outBuffer, sizeof(char), numBytes, fout) != numBytes)
    {
        printf("%s: Error writing output file\n", argv[0]);
        exit(1);
    }
    
    // Clean up
    fclose(fout);
    fclose(fin);
    free(inBuffer);
    free(outBuffer);
    CCCryptorRelease(cryptoRef);
    
    return 0;
}
