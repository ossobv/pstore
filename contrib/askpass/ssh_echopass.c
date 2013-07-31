#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * FIXME: using the filesystem is not really safe
 * but it's better than using the environment...
 * A solution would be to use a bit of both: filesystem for XORed data
 * and the environment for a random key.
 */

int main(int argc, char const *const *argv, char const *const *envp) {
	#define VAR "SSH_PASSWORD"
	while (*envp) {
		if (strncmp(*envp, VAR "=", sizeof(VAR)) == 0) {
			char const *name = *envp + sizeof(VAR);
			FILE *fp = fopen(name, "r+");
			if (fp) {
				#define BUFLEN 128
				char buf[BUFLEN+1];
				buf[0] = buf[BUFLEN] = '\0';
				fgets(buf, BUFLEN, fp);
				fputs(buf, stdout);
				/* Wipe original */
				memset(buf, 'X', BUFLEN);
				fseek(fp, 0, SEEK_SET);
				fwrite(buf, 1, BUFLEN, fp);
				fclose(fp);
				/* Wipe original file */
				unlink(name);
				return 0;
				#undef BUFLEN
			}
			return 1;
		}
		++envp;
	}
	return 1;
	#undef VAR
}
