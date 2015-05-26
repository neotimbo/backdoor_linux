#include <stdio.h>


void send_knock(int port, char *addr)
{
	char buffer[256];
	sprintf(buffer, "sh client.sh %d %s", port, addr);
	system(buffer);
	//system("sh client.sh");
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

int main(int argc, char **argv)
{	
	int port;
	char *host;

	if(argc != 3) {
		printf("USAGE: %s [PORT] [IP ADDR]\n", argv[0]);
		return 2;
	}
	
	host = argv[2];
	port = atoi(argv[1]);

	send_knock(port, host);
	decrypt(19);

	return 0;
}
