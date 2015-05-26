#include <stdio.h>


void send_knock()
{
	system("sh client.sh");
}

void decrypt(int shift)
{
	FILE *infile = fopen("encrypted.txt", "r");
	FILE *outfile = fopen("decrypted.txt", "w");
	char a;

	if (infile == NULL) {
		fclose(infile);
		exit(1);
	}

	if (outfile == NULL) {
		fclose(outfile);
		exit(1);
	}

	do {
		a = fgetc(infile);
		fputc(a - shift, outfile);
	} while(a != EOF);

	fcloseall();
}

int main(int argc, char *argv[])
{
	send_knock();
	decrypt(19);

	return 0;
}
