#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#include <openssl/rc4.h>

int textOff = 0x56a0;
uLongf destLen = 0x7f6c;
int rotextOff = 0xd60c, rotextLen = 0x1e10;

unsigned long get_filesize(const char *path){
    unsigned long filesize = -1;
    struct stat statbuff;
    if (stat(path, &statbuff) < 0){
        return filesize;
    }
    else{
        filesize = statbuff.st_size;
    }
    return filesize;
}

void modifyMagic(char *f){
    *(f+1) = 'E';
    *(f+2) = 'L';
    *(f+3) = 'F';

}


int main(){
    
    const char *filepath = "o";
    int fd, i=0, keyindex = 0, destindex = 0;
    unsigned char rc4key[256] = {0}, keytmp = 0, srctmp=0;

    fd = open(filepath,O_RDWR);
    long fsize = get_filesize(filepath);

    unsigned char *file = mmap(0,fsize,PROT_WRITE|PROT_READ,MAP_SHARED,fd,0);
    close(fd);
    unsigned char *dest = file+textOff;

    modifyMagic(file);
   
    unsigned int *srcLen = dest;
    printf("src length: %d\n", *srcLen);
    char *src = malloc(*srcLen);
    destindex = 4;
    do
    {
        if ( !(i&3) && keyindex <= 0xfe )
        {
            keytmp = dest[destindex];
            ++keyindex;
            ++destindex;
            rc4key[i>>2] = keytmp;
        }
        srctmp = dest[destindex++];
        *(src + i++) = srctmp;
    }
    while(*srcLen != i);

    

    int r = uncompress(dest, &destLen, src, *srcLen);
    printf("%d\n", r);

    unsigned char *rotextAddr = file + rotextOff;
    int keyLen = keyindex;

    printf("key length: %d\n", keyLen);

    for (i = 0; i < keyLen; i++){
        printf("%2x ", rc4key[i]);
    }
    printf("\n");

    unsigned char*rotextsrc = malloc(rotextLen);
    memset(rotextsrc, 0, rotextLen);
    memcpy(rotextsrc, rotextAddr, rotextLen);


    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, keyLen, rc4key);
    RC4(&rc4_key, rotextLen, rotextsrc,rotextAddr);
    

    
    
    munmap(file,fsize);
    free(src);
    free(rotextsrc);


    
    
    

    return 0;
}
