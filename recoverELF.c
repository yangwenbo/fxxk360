#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#include <openssl/rc4.h>
#include <stdint.h>
#include <stdlib.h>


const char *originELFname = "libprotectClass.so";
const char *realELFname = "realELF";

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

int writeFile(unsigned char *src, size_t len, const char* name){
    FILE *fp = 0;
    fp = fopen(name, "wb");
    if (fp == NULL){
        return -1;
    }
    fwrite(src, len, 1, fp);
    fclose(fp);
    return 0;
}

void fix_ELF_Header(const char* name)
{
    int fd = open(name,O_RDWR);
    long fsize = get_filesize(name);
    unsigned char *file = mmap(0,fsize,PROT_WRITE|PROT_READ,MAP_SHARED,fd,0);

    //fix Size of section headers
    *(uint16_t*)(file + 0x2e) = 0x0028;   

    //fix Number of section headers
    uint16_t secHeaderNum = (fsize - *(uint32_t*)(file + 0x20))/0x28;
    *(uint16_t*)(file + 0x30) = secHeaderNum;             

    //fix Section header string table index
    *(uint16_t*)(file + 0x32) = secHeaderNum - 1;
    
    close(fd);
    munmap(file,fsize);

}

int dump_real_ELF(const char* infile, const char* outfile)
{
    //name is unused now
    const char* section_name = ".upx.1";
    size_t offset = 0x10218;
    size_t size = 0x12514;


    int fd = open(infile,O_RDWR);
    unsigned char key[10] = {0x46, 0x45, 0x88, 0x89, 0x98, 0x99, 0x87, 0x87, 0x65, 0x87};
    long fsize = get_filesize(infile);
    unsigned char *file = mmap(0,fsize,PROT_WRITE|PROT_READ,MAP_SHARED,fd,0);


    unsigned char* realELF = malloc(size);
    if (realELF){
        memset(realELF, 0, size);
        memcpy(realELF, file + offset, size);

        RC4_KEY rc4_key;
        RC4_set_key(&rc4_key, 10, key);
        RC4(&rc4_key, size, realELF, realELF);
        if ( writeFile(realELF, size, outfile) != 0 )
        {
            printf("write realELF failed\n");
        }

        free(realELF);
    }
    else{
        printf("malloc failed\n");
    }

    close(fd);
    munmap(file,fsize);
    return 0;
}

int recover_real_ELF(const char* name)
{
    //two section name: .text and .rotext.1
    size_t textOff = 0x56a0, textLen = 0x7f6c;
    size_t rotextOff = 0xd60c, rotextLen = 0x1e10;

    int fd = open(name, O_RDWR);
    long fsize = get_filesize(name);

    unsigned char *file = mmap(0,fsize,PROT_WRITE|PROT_READ,MAP_SHARED,fd,0);
    close(fd);

    modifyMagic(file);

    //use .text to generate rc4key and decrypt rotext and uncompress the text
    unsigned char *dest = file+textOff;
    uint32_t srcLen = *(uint32_t*)dest;
    printf("src length: %d\n", srcLen);
    unsigned char *src = malloc(srcLen);
    unsigned int destindex = 4, i = 0, keyindex = 0;
    unsigned char rc4key[256] = {0}, keytmp = 0, srctmp = 0;

    //generate key and text src
    do
    {
        if ( !(i & 3) && keyindex <= 0xfe )
        {
            keytmp = dest[destindex];
            ++keyindex;
            ++destindex;
            rc4key[i>>2] = keytmp;
        }
        srctmp = dest[destindex++];
        *(src + i++) = srctmp;
    }
    while(srcLen != i);

    
    // uncompress text
    int r = uncompress(dest, &textLen, src, srcLen);
    printf("%d\n", r);

    //decrypt rotext
    unsigned char *rotextAddr = file + rotextOff;
    unsigned int keyLen = keyindex;

    printf("key length: %d\n", keyLen);

    for (i = 0; i < keyLen; i++){
        printf("%2x ", rc4key[i]);
    }
    printf("\n");


    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, keyLen, rc4key);
    RC4(&rc4_key, rotextLen, rotextAddr, rotextAddr);
    
    munmap(file,fsize);
    free(src);


    return 0;
}


int main(){

    fix_ELF_Header(originELFname);

    dump_real_ELF(originELFname, realELFname);

    recover_real_ELF(realELFname);

    return 0;
}
