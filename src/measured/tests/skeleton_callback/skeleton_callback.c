#include <stdio.h>

/*
 * Very simple program to show how tests can be run.
 */
int main(int argc, char *argv[]) {
    int i;

    printf("skeleton callback test\n");
    printf("argc: %d\n", argc);

    for ( i=0; i<argc; i++)  {
	printf("argv[%d]: %s\n", i, argv[i]);
    }

    return 0;
}
