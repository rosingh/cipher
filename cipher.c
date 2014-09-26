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

void print_usage(void);
void check_files(const char *infile, const char *outfile);
void open_files(const char *infile, const char *outfile, int *infile_des, int *outfile_des);
void encdec_file(const char *infile, const char *outfile, char *password, const int enc_flag);
void close_file(const char *file, int *file_des);

int main(int argc, char *argv[])
{
	char arg;
	char *password;
	const char *infile;
	const char *outfile;

	int dflag = 0;
	int eflag = 0;
	int pflag = 0;
	int hflag = 0;
	int vflag = 0;
	int errflag = 0;

	while (!errflag && ((arg = getopt(argc, argv, "devhp:")) != -1))
	{
		switch(arg)
		{
			case 'p':
				if (pflag)
				{
					++errflag;
					break;
				}
				password = optarg;
				++pflag;
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
				++vflag;
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
		return hflag;
	}

	// If flag sequence was invalid (invalid flag or duplicate flags) then exit
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

	// If neither -d or -e was specified print error and exit
	if (!dflag && !eflag)
	{
		fprintf(stderr, "Error: Must specify -d or -e\n");
		print_usage();
		exit(EX_USAGE);
	}

	// If both file names are not specified, print error and exit
	if (argc != optind + 2)
	{
		fprintf(stderr, "Error: Invalid number of file names\n");
		print_usage();
		exit(EX_USAGE);
		
	}

	infile = argv[optind];
	outfile = argv[optind + 1];

	// If a password wasn't supplied as an argument, get it now
	if (!pflag)
	{
		password = getpass("Enter a password: ");
	}

	encdec_file(infile, outfile, password, eflag);

	/*
	 * This is how you encrypt an input char* buffer "from", of length "len"
	 * onto output buffer "to", using key "key".  Jyst pass "iv" and "&n" as
	 * shown, and don't forget to actually tell the function to BF_ENCRYPT.
	 */
	//BF_cfb64_encrypt(from, to, len, &key, iv, &n, BF_ENCRYPT);

	/* Decrypting is the same: just pass BF_DECRYPT instead */
	//BF_cfb64_encrypt(from, to, len, &key, iv, &n, BF_DECRYPT);
	exit(0);
}

/*
 * Prints usage text for the program
 */
void print_usage(void)
{
	fprintf(stderr, "usage: cipher [-devh] [-p PASSWD] infile outfile\n");
}

/*
 * Checks files for any possible errors before openng them
 * Exits the program if possible errors are detected
 * infile - name for the input file, "-" for stdin
 * outfile - name for the output file, "-" for stdout
 */
void check_files(const char *infile, const char *outfile)
{
	struct stat infile_stat;
	struct stat outfile_stat;

	int istat = stat(infile, &infile_stat);
	int ostat = stat(outfile, &outfile_stat);


	// Only go through file checks if infile is not set to stdin
	if (strcmp(infile, "-") != 0)
	{
		// There was an error getting stats for infile
		if (istat == -1)
		{
			perror(infile);
			exit(errno);
		}

		// File is a directory so exit
		if (S_ISDIR(infile_stat.st_mode))
		{
			fprintf(stderr, "%s is a directory\n", infile);
			exit(EX_USAGE);
		}

		// Don't have read permissions to infile so exit
		if ((infile_stat.st_mode & S_IRUSR) != S_IRUSR)
		{
			fprintf(stderr, "You do not have read permission for %s\n", infile);
			exit(EX_NOINPUT);
		}

	}

	// Only go through file checks if outfile is not set to stdout
	if (strcmp(outfile, "-") != 0)
	{
		// There was an error getting stats for outfile
		if (ostat == -1)
		{
			// If file doesn't exist then just return since it can be created later
			if (errno == ENOENT)
			{
				return;
			}
			// Some other reason getting stats failed so print error and exit
			else
			{
				perror(outfile);
				exit(errno);
			}
		}

		// File is a directory so exit
		if (S_ISDIR(outfile_stat.st_mode))
		{
			fprintf(stderr, "%s is a directory\n", outfile);
			exit(EX_USAGE);
		}

		// Don't have write permission to outfile so exit
		if ((outfile_stat.st_mode & S_IWUSR) != S_IWUSR)
		{
			fprintf(stderr, "You do not have write permission for %s\n", outfile);
			exit(EX_NOINPUT);
		}
	}

	// Check if both filepaths actually point to the same file.
	// If they do then exit
	if ((strcmp(infile, "-") != 0 && strcmp(outfile, "-") != 0) && 
		(infile_stat.st_dev == outfile_stat.st_dev) && 
		(infile_stat.st_ino == outfile_stat.st_ino))
	{
		fprintf(stderr, "infile and outfile must be different\n");
		exit(EX_USAGE);
	}
	
}

/*
 * Opens both infile and outfile and returns the file descriptors
 * Will exit if it fails to open a file
 */
void open_files(const char *infile, const char *outfile, int *infile_des, int *outfile_des)
{
	// if infile == "-" then use stdin
	if (strcmp(infile, "-") == 0)
	{
		*infile_des = STDIN_FILENO;
	}
	// Try to open the file, if it fails exit
	else if ((*infile_des = open(infile, O_RDONLY)) < 0)
	{
		perror(infile);
		exit(errno);
	}

	// If outfile == "-" then use stdout
	if (strcmp(outfile, "-") == 0)
	{
		*outfile_des = STDOUT_FILENO;
	}
	// Try to open the file, if it fails exit
	else if ((*outfile_des = open(outfile, O_WRONLY | O_CREAT, S_IRWXU)) < 0)
	{
		perror(outfile);
		close_file(infile, infile_des);
		exit(errno);
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
	// zero out the PW now
	memset(password, 0, strlen(password));
	fprintf(stdout, "%s\n", password);

	int tempfile_des;
	char temp_template[] = "temp.XXXXXX";
	if ((tempfile_des = mkstemp(temp_template)) < 0)
	{
		fprintf(stderr, "Failed to make temp file\n%s\n", strerror(errno));
		exit(EX_CANTCREAT);
	}

	// Check files and declare variables for infile and outfile descriptors
	check_files(infile, outfile);
	int infile_des;
	int outfile_des;

	// Try to open both files
	open_files(infile, outfile, &infile_des, &outfile_des);



	// Get the page size
	const int page_size = getpagesize();

	// Try to 
	unsigned char *input_buffer;
	if ((input_buffer = (unsigned char *) malloc(sizeof(unsigned char) * page_size)) == NULL)
	{
		// malloc failed so close files and exit
		fprintf(stderr, "%s\n", strerror(errno));
		close_file(infile, &infile_des);
		close_file(outfile, &outfile_des);
		unlink(outfile);
		exit(errno);
	}
	
	unsigned char *output_buffer;
	if ((output_buffer = (unsigned char *) malloc(sizeof(unsigned char) * page_size)) == NULL)
	{
		// malloc failed so free input buffer, close files and exit
		fprintf(stderr, "%s\n", strerror(errno));
		free(input_buffer);
		close_file(infile, &infile_des);
		close_file(outfile, &outfile_des);
		unlink(outfile);
		exit(errno);
	}

	int enc_or_dec;
	if(enc_flag == 1)
	{
		enc_or_dec = BF_ENCRYPT;
	}
	else
	{
		enc_or_dec = BF_DECRYPT;
	}

	int bytes_read;
	int bytes_written;
	while ((bytes_read = read(infile_des, input_buffer, page_size)) > 0)
	{
		BF_cfb64_encrypt(input_buffer, output_buffer, bytes_read, &key, iv, &n, enc_or_dec);
		// If there is an error with writing, close and free everything and exit
		if ((bytes_written = write(outfile_des, output_buffer, bytes_read)) <= 0)
		{
			perror(outfile);
			free(input_buffer);
			free(output_buffer);
			close_file(infile, &infile_des);
			close_file(outfile, &outfile_des);
			unlink(outfile);
			exit(errno);
		}
	}

	// If there was an error in reading, close everything and exit
	if (bytes_read < 0)
	{
		perror(infile);
		free(input_buffer);
		free(output_buffer);
		close_file(infile, &infile_des);
		close_file(outfile, &outfile_des);
		unlink(outfile);
		exit(errno);
	}

	// Print a newline to terminal if outputting to stdout
	if (outfile_des == STDOUT_FILENO)
	{
		fprintf(stdout, "\n");
	}

	// Cleanup
	free(input_buffer);
	free(output_buffer);
	close_file(infile, &infile_des);
	close_file(outfile, &outfile_des);
}

/*
 * Close the file, if there is an error print it
 */
void close_file(const char *file, int *file_des)
{
	if (close(*file_des) < 0)
	{
		perror(file);
	}
}
