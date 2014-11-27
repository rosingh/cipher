#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include "blowfish.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/statvfs.h>

void print_usage(void);
void check_files(const char *infile, const int infile_des, const char *outfile, const int outfile_des);
void open_files(const char *infile, const char *outfile, int *infile_des, int *outfile_des);
void encdec_file(const char *infile, const char *outfile, char *password, const int enc_flag);
void close_file(const char *file, int file_des);

/*
 * Entry point of program
 * Handles arguments with getopt and any argument errors
 * Also handles password creation
 */
int main(int argc, char *argv[])
{
	char arg;
	char *password = NULL;
	const char *infile;
	const char *outfile;

	/* Argument flags */
	int dflag = 0;
	int eflag = 0;
	int pflag = 0;
	int hflag = 0;
	int vflag = 0;
	int sflag = 0;
	int errflag = 0;

	/* Parses arguments and sets flags accordingly
	 * If errflag is triggered then break the loop
	 */
	while (!errflag && ((arg = getopt(argc, argv, "devhsip:")) != -1))
	{
		switch(arg)
		{
			case 'p':
				if (pflag || sflag)
				{
					++errflag;
					break;
				}
				++pflag;
				/* copy password over from optarg */
				password = (char *) malloc(sizeof(char) * (strlen(optarg) + 1));
				if (password == NULL)
				{
					fprintf(stderr, "%s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				strncpy(password, optarg, strlen(optarg));
				password[strlen(optarg)] = '\0';
				break;

			case 'd':
				if (dflag || eflag)
				{
					++errflag;
					break;
				}
				++dflag;
				break;

			case 'e':
				if (dflag || eflag)
				{
					++errflag;
					break;
				}
				++eflag;
				break;

			case 'h':
				++errflag;
				++hflag;
				break;

			case 'v':
				if (vflag)
				{
					++errflag;
					break;
				}
				++vflag;
				break;

			case 's':
				if (pflag || sflag)
				{
					++errflag;
					break;
				}
				++sflag;
				break;

			case '?':
				++errflag;
				break;

			default:
				++errflag;
				break;
		}
	}

	if (hflag)
	{
		print_usage();
		exit(EX_USAGE);
	}

	/* If flag sequence was invalid (invalid flag or duplicate flags) then exit */
	if (errflag)
	{
		fprintf(stderr, "Error: Unknown or invalid argument sequence\n");
		print_usage();
		exit(EX_USAGE);
	}

	if (vflag)
	{
		fprintf(stderr, "v1.0\n");
	}

	/* If neither -d or -e was specified print error and exit */
	if (!dflag && !eflag)
	{
		fprintf(stderr, "Error: Must specify -d or -e\n");
		print_usage();
		exit(EX_USAGE);
	}

	/* If both file names are not specified, print error and exit */
	if (argc != optind + 2)
	{
		fprintf(stderr, "Error: Invalid number of file names\n");
		print_usage();
		exit(EX_USAGE);
	}

	infile = argv[optind];
	outfile = argv[optind + 1];

	/* If a password wasn't supplied as an argument, get it now */
	if (!pflag)
	{
		char *tmp_buffer = getpass("Enter a password: ");
		char *pw_buffer1 = (char *) malloc(sizeof(char) * (strlen(tmp_buffer) + 1));
		if (pw_buffer1 == NULL)
		{
			fprintf(stderr, "%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		/* copy over the characters from the getpass buffer to the buffer to work on */
		strncpy(pw_buffer1, tmp_buffer, strlen(tmp_buffer));
		/* ensure the buffer is null terminated */
		pw_buffer1[strlen(tmp_buffer)] = '\0';
		/* null out the tmp buffer now */
		memset(tmp_buffer, 0, strlen(tmp_buffer));
		tmp_buffer = NULL;
		if (sflag)
		{
			tmp_buffer = getpass("Confirm the password: ");
			char *pw_buffer2 = (char *) malloc(sizeof(char) * (strlen(tmp_buffer) + 1));
			if (pw_buffer2 == NULL)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			/* copy over the characters from the getpass buffer to the buffer to work on */
			strncpy(pw_buffer2, tmp_buffer, strlen(tmp_buffer));
			/* ensure the buffer is null terminated */
			pw_buffer2[strlen(tmp_buffer)] = '\0';
			/* null out the tmp buffer now */
			memset(tmp_buffer, 0, strlen(tmp_buffer));
			tmp_buffer = NULL;

			/* Now compare the two passwords to see if they are equal
			 * If not, exit */
			if (strcmp(pw_buffer1, pw_buffer2) != 0)
			{
				fprintf(stderr, "Passwords do not match\n");
				free(pw_buffer1);
				free(pw_buffer2);
				exit(EX_USAGE);
			}
			free(pw_buffer2);
		}
		password = pw_buffer1;
	}

	encdec_file(infile, outfile, password, eflag);
	free(password);

	exit(EXIT_SUCCESS);
}

/*
 * Prints usage text for the program
 */
void print_usage(void)
{
	fprintf(stderr, "usage: cipher [-devhs] [-p PASSWD] infile outfile\n");
}

/*
 * Checks files for any possible errors before opening them
 * Exits the program if possible errors are detected
 * infile - name for the input file, "-" for stdin
 * outfile - name for the output file, "-" for stdout
 */
void check_files(const char *infile, const int infile_des, const char *outfile, const int outfile_des)
{
	struct stat infile_stat;
	struct stat outfile_stat;

	int istat = fstat(infile_des, &infile_stat);
	int ostat = fstat(outfile_des, &outfile_stat);


	/* Only go through file checks if infile is not set to stdin */
	if (strcmp(infile, "-") != 0)
	{
		/* There was an error getting stats for infile */
		if (istat == -1)
		{
			perror(infile);
			close_file(infile, infile_des);
			close_file(outfile, outfile_des);
			exit(EX_NOINPUT);
		}

		/* File is a directory so exit */
		if (!S_ISREG(infile_stat.st_mode))
		{
			if (S_ISDIR(infile_stat.st_mode))
			{
				fprintf(stderr, "%s is a directory\n", infile);
				close_file(infile, infile_des);
				close_file(outfile, outfile_des);
				exit(EX_USAGE);
			}
			else
			{
				fprintf(stderr, "%s is a block or character special\n", infile);
				close_file(infile, infile_des);
				close_file(outfile, outfile_des);
				exit(EX_USAGE);
			}
		}
	}

	/* Only go through file checks if outfile is not set to stdout */
	if (strcmp(outfile, "-") != 0)
	{
		/* There was an error getting stats for outfile */
		if (ostat == -1)
		{
			/* If file doesn't exist then just return since it can be created later */
			if (errno == ENOENT)
			{
				return;
			}
			/* Some other reason getting stats failed so print error and exit */
			else
			{
				perror(outfile);
				close_file(infile, infile_des);
				close_file(outfile, outfile_des);
				exit(EX_NOINPUT);
			}
		}

		/* File is a directory so exit */
		if (!S_ISREG(outfile_stat.st_mode))
		{
			if (S_ISDIR(outfile_stat.st_mode))
			{
				fprintf(stderr, "%s is a directory\n", outfile);
				close_file(infile, infile_des);
				close_file(outfile, outfile_des);
				exit(EX_USAGE);
			}
			else
			{
				fprintf(stderr, "%s is a block or character special\n", outfile);
				close_file(infile, infile_des);
				close_file(outfile, outfile_des);
				exit(EX_USAGE);
			}
		}
	}

	/* Check if both filepaths actually point to the same file.
	 * If they do then exit */
	if ((strcmp(infile, "-") != 0 && strcmp(outfile, "-") != 0) && 
		(infile_stat.st_dev == outfile_stat.st_dev) && 
		(infile_stat.st_ino == outfile_stat.st_ino))
	{
		fprintf(stderr, "Error: %s and %s are the same file\n", infile, outfile);
		close_file(infile, infile_des);
		close_file(outfile, outfile_des);
		exit(EX_USAGE);
	}
	/* check if file system has enough space */
	if (strcmp(infile, "-") != 0 && strcmp(outfile, "-") != 0)
	{
		struct statvfs fsinfo;
		if (fstatvfs(outfile_des, &fsinfo) < 0)
		{
			perror(outfile);
			close_file(infile, infile_des);
			close_file(outfile, outfile_des);
			exit(EX_NOINPUT);
		}
		long free_space = fsinfo.f_bsize * fsinfo.f_bfree;
		if (free_space < infile_stat.st_size)
		{
			fprintf(stderr, "Not enough free space on file system\n");
			close_file(infile, infile_des);
			close_file(outfile, outfile_des);
			exit(EX_CANTCREAT);
		}
	}
}

/*
 * Opens both infile and outfile and returns the file descriptors
 * Will exit if it fails to open a file
 */
void open_files(const char *infile, const char *outfile, int *infile_des, int *outfile_des)
{
	/* if infile == "-" then use stdin */
	if (strcmp(infile, "-") == 0)
	{
		*infile_des = fileno(stdin);
	}
	/* Try to open the file, if it fails exit */
	else if ((*infile_des = open(infile, O_RDONLY)) < 0)
	{
		perror(infile);
		exit(EX_NOINPUT);
	}

	/* If outfile == "-" then use stdout */
	if (strcmp(outfile, "-") == 0)
	{
		*outfile_des = fileno(stdout);
	}
	/* Try to open the file, if it fails exit */
	else if ((*outfile_des = open(outfile, O_WRONLY | O_CREAT, S_IRWXU)) < 0)
	{
		perror(outfile);
		close_file(infile, *infile_des);
		exit(EX_CANTCREAT);
	}
}

/*
 * Encrypts or decrypts the file depending on what enc_flag is set to
 * infile - name of the infile
 * outfile - nmae of the outfile
 * password - the password to use for encrypting/decrypting
 * enc_flag - if 1 encrypt, else decrypt
 */
void encdec_file(const char *infile, const char *outfile, char *password, const int enc_flag)
{
	/* define a structure to hold the key */
	BF_KEY key;

	/* don't worry about these two: just define/use them */
	int n = 0;			/* internal blowfish variables */
	unsigned char iv[8];		/* Initialization Vector */

	/* fill the IV with zeros (or any other fixed data) */
	memset(iv, 0, 8);

	/* call this function once to setup the cipher key */
	BF_set_key(&key, strlen(password), (unsigned char *) password);

	int infile_des;
	int outfile_des;
	/* Try to open both files and check for errors */
	open_files(infile, outfile, &infile_des, &outfile_des);
	check_files(infile, infile_des, outfile, outfile_des);


	/* Get the page size */
	const int page_size = getpagesize();

	/* Try to allocate memory for the input buffer */
	unsigned char *input_buffer;
	if ((input_buffer = (unsigned char *) malloc(sizeof(unsigned char) * page_size)) == NULL)
	{
		/* malloc failed so exit */
		fprintf(stderr, "%s\n", strerror(errno));
		close_file(infile, infile_des);
		close_file(outfile, outfile_des);
		unlink(outfile);
		exit(EXIT_FAILURE);
	}
	
	/* Try to allocate memory for the output buffer */
	unsigned char *output_buffer;
	if ((output_buffer = (unsigned char *) malloc(sizeof(unsigned char) * page_size)) == NULL)
	{
		/* malloc failed so free input buffer, close files and exit */
		fprintf(stderr, "%s\n", strerror(errno));
		free(input_buffer);
		close_file(infile, infile_des);
		close_file(outfile, outfile_des);
		unlink(outfile);
		exit(EXIT_FAILURE);
	}

	/* Set behavior to encrypt or decrypt */
	int enc_or_dec;
	if (enc_flag == 1)
	{
		enc_or_dec = BF_ENCRYPT;
	}
	else
	{
		enc_or_dec = BF_DECRYPT;
	}

	int bytes_read;
	int bytes_written;
	/* Read/write loop. If an error occurs program will halt and exit */
	while ((bytes_read = read(infile_des, input_buffer, page_size)) > 0)
	{
		BF_cfb64_encrypt(input_buffer, output_buffer, bytes_read, &key, iv, &n, enc_or_dec);
		/* If there is an error with writing, close and free everything and exit */
		if ((bytes_written = write(outfile_des, output_buffer, bytes_read)) <= 0)
		{
			perror(outfile);
			free(input_buffer);
			free(output_buffer);
			close_file(infile, infile_des);
			close_file(outfile, outfile_des);
			unlink(outfile);
			exit(EXIT_FAILURE);
		}
	}

	/* If there was an error in reading, close everything and exit */
	if (bytes_read < 0)
	{
		perror(infile);
		free(input_buffer);
		free(output_buffer);
		close_file(infile, infile_des);
		close_file(outfile, outfile_des);
		unlink(outfile);
		exit(EXIT_FAILURE);
	}

	/* Print a newline to terminal if outputting to stdout */
	if (outfile_des == STDOUT_FILENO)
	{
		fprintf(stdout, "\n");
	}

	/* Cleanup */
	free(output_buffer);
	free(input_buffer);
	close_file(infile, infile_des);
	close_file(outfile, outfile_des);
}

/*
 * Close the file, if there is an error print it
 */
void close_file(const char *file, int file_des)
{
	if (close(file_des) < 0)
	{
		perror(file);
	}
}
