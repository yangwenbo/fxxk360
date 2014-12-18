#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#include <openssl/rc4.h>
#include "LzmaDec.h"
#include <stdlib.h>

//need for lzma
static void *SzAlloc(void *p, size_t size) { p = p; return malloc(size); }
static void SzFree(void *p, void *address) { p = p; free(address); }
static ISzAlloc g_Alloc = { SzAlloc, SzFree };

size_t get_filesize(const char *path){
	size_t filesize = 0;
	struct stat statbuff;
	if (stat(path, &statbuff) < 0){	
		return filesize;
	}
	else{
		filesize = statbuff.st_size;
		printf("%lx\n", filesize);
	}
	return filesize;
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

int main(){

	const char *filepath = "classes.dex";
	int fd;
	SRes v9;

	unsigned char key[20], dest[8] = {0}, s[256] = {0};
	size_t size = 0, len = 0, fsize = 0;
	unsigned char *decDest;
	void * decSrc;
	ELzmaStatus status;

	fd = open(filepath,O_RDWR);
	fsize = get_filesize(filepath);

	unsigned char *file = mmap(0, fsize, PROT_WRITE|PROT_READ,MAP_SHARED, fd, 0);

	close(fd);

	unsigned int *tmpoff1 = (unsigned int*)(file + 104), *tmpoff2 = (unsigned int*)(file + 108);
	//memcpy(&fsize, (const void*)(file + 32), 4);                     //dex 32 offset is file size
	size_t tmpsize = 0;
	tmpsize = *tmpoff1 + *tmpoff2;
	
	unsigned char *qhOff = file + tmpsize;             // calculate padding offset beginning with 'qh'

	size_t paddingSize = fsize - tmpsize;

	memset(&key, 0, 20);
	memcpy(&key, (const void*)(qhOff + 264), 20);
	memcpy(&dest, (const void*)(qhOff + 284), 5);
	memcpy(&len, (const void*)(qhOff + 289), 4);
	memcpy(&size, (const void*)(qhOff + 293), 4);

	printf("size: %lx\n", size);
	printf("paddingsize: %lx\n", paddingSize);


	//lzma decode after rc4 decrypt
	if (size <= paddingSize)
	{
		decSrc = malloc(size);

		if (decSrc){
			
			memset(decSrc, 0, size);
			memcpy(decSrc, (const void*)(qhOff + 297), size);
	
			RC4_KEY rc4_key;
			RC4_set_key(&rc4_key, 16, (key+4));
			RC4(&rc4_key, size, decSrc, decSrc);

			decDest = mmap(0, len, PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

			v9 = LzmaDecode(decDest, (SizeT*)&len, decSrc, &size, (unsigned char*)&dest, 5, 0, &status, &g_Alloc); 
			printf("%d", v9 );


			free(decSrc);

			if (v9 != SZ_OK)
			{
				munmap(decDest,len);
			}
		}
	}
	
	//recover the dex header
	int i = 0;
	
	if (decDest)
	{
		do {
			*(decDest + i++) ^= *key;

		}while(i != 112);
	}

	for (i = 0; i < 112; i++){
		printf("%x ", decDest[i]);
	}

	if (writeFile(decDest, len, "un.dex") == -1)
	{
		printf("write file failed\n");
	}

	munmap(file,fsize); 
	munmap(decDest,len);


	return 0;
}