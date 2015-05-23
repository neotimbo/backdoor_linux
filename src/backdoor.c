#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>



#define MASK "BACKDOOR"
void mask_application(char *name)
{
	memset(name, 0, strlen(name));
	strcpy(name, MASK);
	prctl(PR_SET_NAME, MASK, 0, 0);

	setuid(0);
	setgid(0);
}


int main(int argc, char *argv[])
{
	mask_application(argv[0]);



	while(1){}

	return 0;

}
