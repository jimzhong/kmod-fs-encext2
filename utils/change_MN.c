#include <stdio.h>
int main(int argc, char **argv)
{
	int ret;
	FILE *fp;
	unsigned char buf[2048];

	fp=fopen(argv[1], "rb+");

	if(fp == NULL)
	{
		printf("open file failed!\n");
		return 1;
	}

	ret=fread(buf,sizeof(unsigned char),2048,fp);
	if (ret < 2048)
	{
		printf("File too small.\n");
		return 1;
	}

	printf("previous magic number is 0x%x%x\n",buf[0x438],buf[0x439]);

	buf[0x438]=0x66;
	buf[0x439]=0x66;

	fseek(fp, 0, SEEK_SET);
	fwrite(buf,sizeof(unsigned char),2048,fp);

	fseek(fp, 0, SEEK_SET);
	ret=fread(buf,sizeof(unsigned char),2048,fp);
	printf("current magic number is 0x%x%x\n",buf[0x438],buf[0x439]);

	fclose(fp);

	return 0;
}
