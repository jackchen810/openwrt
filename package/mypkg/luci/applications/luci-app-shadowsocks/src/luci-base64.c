#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define PROGRAM_NAME "base64"
#define VERSION "1.0.0"

static struct option const long_options[] =
{
  {"decode", no_argument, 0, 'd'},
  {"encode", no_argument, 0, 'e'},
  {"output", required_argument, 0, 'o'},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'v'},

  {NULL, 0, NULL, 0}
};

enum app_usage
{
	INVALID,
	ENCODE,
	DECODE
};

static const int CHARACTERS_PER_LINE = 72;
static const char BASE64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void usage(void)
{
	fprintf(stdout, "Usage: %s [OPTION]... [FILE] [OUTPUT]\n", PROGRAM_NAME);
	fprintf(stdout, "Options:\n");
	fprintf(stdout, "  -d, --decode          decode data\n");
	fprintf(stdout, "  -e, --encode          encode data\n");
	fprintf(stdout, "  -o, --output          specifies output file\n");
	fprintf(stdout, "  -h, --help            display this help and exit.\n");
	fprintf(stdout, "  -v, --version         output version information and exit.\n");
	exit(EXIT_FAILURE);
}

void base64_encode(FILE* input, FILE* output)
{
	unsigned char data[3];
	unsigned char code[4];
	int done, i, ch, chcnt = 0;

	done = 0;
	while (!done)
	{
		data[0] = data[1] = data[2] = '\0';

		for (i = 0; i < 3; i++)
		{
			if ((ch = fgetc(input)) == -1)
			{
				done = 1;
				break;
			}

			data[i] = (unsigned char)ch;
		}

		if (i > 0)
		{
			code[0] = BASE64_TABLE[ (data[0] & 0xfc) >> 2];
			code[1] = BASE64_TABLE[((data[0] & 0x03) << 4) | ((data[1] & 0xf0) >> 4)];
			code[2] = BASE64_TABLE[((data[1] & 0x0f) << 2) | ((data[2] & 0xc0) >> 6)];
			code[3] = BASE64_TABLE[  data[2] & 0x3f];

			memset(code + i + 1, '=', 3 - i);

			for (i = 0; i < 4; i++)
				putc(code[i], output);

			chcnt += 4;

			if (chcnt >= CHARACTERS_PER_LINE)
			{
				putc('\n', output);
				chcnt = 0;
			}
		}
	}

	putc('\n', output);
}

void base64_decode(FILE* input, FILE* output)
{
	unsigned char data[3];
	unsigned int  code[4];
	int done, ch, i, j;

	done = 0;
	while (!done)
	{
		code[0] = code[1] = code[2] = code[3] = 0;

		for (i = 0; i < 4; i++)
		{
			if ((ch = fgetc(input)) == -1 || ch == '=')
			{
				done = 1;
				break;
			}

			if ('A' <= ch && ch <= 'Z')
				code[i] = ch - 'A';
			else if ('a' <= ch && ch <= 'z')
				code[i] = ch - 'a' + ('Z' - 'A' + 1);
			else if ('0' <= ch && ch <= '9')
				code[i] = ch - '0' + ('Z' - 'A' + 1) + ('z' - 'a' + 1);
			else if (ch == '+')
				code[i] = 62;
			else if (ch == '/')
				code[i] = 63;
			else
				i--;
		}

		if (i != 4 && i != 0 && ch != '=')
		{
			fprintf(stderr, "\nIncomplete input\n");
		}
		else if (i != 0)
		{
			data[0] = (unsigned char)(( code[0]         << 2) | ((code[1] & 0x30) >> 4));
			data[1] = (unsigned char)(((code[1] & 0x0F) << 4) | ((code[2] & 0x3C) >> 2));
			data[2] = (unsigned char)(((code[2] & 0x03) << 6) |   code[3]);

			for (j = 0; j < i - 1; j++)
				putc(data[j], output);
		}
	}
}

int main(int argc, char* argv[])
{
	enum app_usage type = INVALID;
	FILE* output = stdout;
	FILE* input = NULL;
	int opt;

	const char* infile;
	
	while ((opt = getopt_long(argc, argv, "deo:hv", long_options, NULL)) != -1) {
		switch(opt) {
			case 'd':
				type = DECODE;
				break;
			case 'e':
				type = ENCODE;
				break;
			case 'o':
				if (!optarg || !(output = fopen(optarg, "wb"))) {
					perror(optarg);
					exit(EXIT_FAILURE);
				};
				break;
			case 'h':
				usage();
				break;
			case 'v':
				fprintf(stdout, "This is ta de version " VERSION "\n");
				break;
			default:
				usage();
				break;
		}
	}
	
	if (argc < 2 || argc - optind > 1) {
		usage();		
	}
	
	if (optind < argc) {
		if ((input = fopen(argv[optind], "rb")) == NULL) {
			perror(argv[optind]);
			exit(EXIT_FAILURE);
		}
	}
	else {
		freopen(NULL, "rb", stdin);
		input = stdin;
	}

	if (type == ENCODE)
		base64_encode(input, output);
	else if (type == DECODE)
		base64_decode(input, output);

	if (input != stdin)
		fclose(input);

	if (output != stdout)
		fclose(output);

	return 0;
}
