/*******************************************************************************
 * Name        : minishell2.c
 * Author      : Owen Krupa
 ******************************************************************************/

 // New minishell which I will be updating!

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <dirent.h>

#define BLUE "\x1b[34;1m"
#define DEFAULT "\x1b[0m"
#define LIGMA 2

volatile sig_atomic_t interrupted = 0;


// To add more commands, make sure to add a command identifier to 'typedef enum' and 'getCommand'
// Enum representing command identifiers
typedef enum {
    CMD_EXIT,
    CMD_CD,
    CMD_PWD,
    CMD_LF,
    CMD_LP,
    CMD_SEPT,
    CMD_UNKNOWN // This should always be the last enum member
} Command;

// Function to convert command string to enum value
Command getCommand(const char* cmd) {
    if (strcmp(cmd, "exit") == 0) {
        return CMD_EXIT;
    } else if (strcmp(cmd, "cd") == 0) {
        return CMD_CD;
    } else if (strcmp(cmd, "pwd") == 0) {
        return CMD_PWD;
    } else if (strcmp(cmd, "lf") == 0) {
        return CMD_LF;
    } else if (strcmp(cmd, "lp") == 0) {
        return CMD_LP;
    } else if (strcmp(cmd, "sept") == 0) {
        return CMD_SEPT;
    } else {
        return CMD_UNKNOWN;
    }
}

void sigint_handler(int signum) {
    write(STDOUT_FILENO, "\n", 1); // Safely write a newline to stdout
    interrupted = 1;
    //fflush(stdout);
}

void execute_pwd() {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("%s\n", cwd);
    } else {
        fprintf(stderr, "Error: Cannot get current working directory. %s.\n", strerror(errno));
    }
}

void execute_lf() {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0) {
                printf("%s\n", dir->d_name);
            }
        }
        closedir(d);
    } else {
        fprintf(stderr, "Error: Failed to open the current directory. %s.\n", strerror(errno));
    }
}

void execute_lp() {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        fprintf(stderr, "Error: Cannot open /proc directory.\n");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR && strspn(entry->d_name, "0123456789") == strlen(entry->d_name)) {
            char path[512];
            snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
            FILE *cmdline_file = fopen(path, "r");
            char cmdline[1024] = {0}; // Initialize with zeros to handle empty cmdline
            if (cmdline_file) {
                size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file);
                fclose(cmdline_file);
                if (bytes_read > 0) {
                    // Replace null characters with spaces, except for the last character
                    for (size_t i = 0; i < bytes_read - 1; ++i) {
                        if (cmdline[i] == '\0') cmdline[i] = ' ';
                    }
                }
            }
            // Get UID and username
            snprintf(path, sizeof(path), "/proc/%s", entry->d_name);
            struct stat statbuf;
            if (stat(path, &statbuf) == 0) {
                struct passwd *pw = getpwuid(statbuf.st_uid);
                if (pw) {
                    printf("%s %s %s\n", entry->d_name, pw->pw_name, cmdline);
                }
            }
        }
    }
    closedir(proc_dir);
}

void execute_cd(char* args) {
    char* path = args;
    char* tildePos = strchr(path, '~');
    char* newPath = NULL;
    struct passwd *pw;
    uid_t uid;

    uid = getuid();
    pw = getpwuid(uid);

    if (args == NULL || strcmp(args, "~") == 0) {
        // uid = getuid();
        // pw = getpwuid(uid);

        if (pw == NULL) {
            fprintf(stderr, "Error: Cannot get passwd entry. %s.\n", strerror(errno));
            return;
        }
        // Home directory
        path = pw->pw_dir; 
    }
    else if (tildePos != NULL) {
        // Account for ~/../..
        int beforeTilde = tildePos - path;
        int afterTilde = strlen(path) - beforeTilde - 1;
        int newLen = beforeTilde + strlen(pw->pw_dir) + afterTilde;
        newPath = (char*)malloc(newLen + 1);
        if (newPath != NULL) {
            // Copy parts into the new string
            strncpy(newPath, path, beforeTilde); // Copy part before the tilde
            newPath[beforeTilde] = '\0';
            strcat(newPath, pw->pw_dir); // Copy replacement string
            strcat(newPath, path + beforeTilde + 1);
            path = newPath;
        }
        else {
            fprintf(stderr, "Error: malloc() failed. %s.\n", strerror(errno));
            return;
        }
    }

    // Attempt to change directory
    if (chdir(path) != 0) {
        fprintf(stderr, "Error: Cannot change directory to %s. %s.\n", path, strerror(errno));
    }

    if (newPath != NULL) {
        free(newPath); // Free the allocated memory
    }
}

int main(void) {
    char cmd[1024];
    char cwd[1024];

    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    //sa.sa_flags = SA_RESTART; // To handle certain system calls
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "Error: Cannot register signal handler. %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    while (1) {
        if (interrupted) {
            interrupted = 0;
            continue;
        }

        // Print prompt
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            fprintf(stderr, "Error: Cannot get current working directory. %s.\n", strerror(errno));
            continue;
        }

        printf(BLUE "[%s]" DEFAULT " > ", cwd);
        fflush(stdout);

        if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
            if (interrupted) {
                interrupted = 0;
                continue;
            }
            if (errno == EINTR) {
                continue; // If interrupted by signal
            }
            fprintf(stderr, "Error: Failed to read from stdin. %s.\n", strerror(errno));
            continue;
        }

        if (interrupted) {
            //printf("are we here?");
            interrupted = 0;
            continue;
        }

        // Strip newline
        cmd[strcspn(cmd, "\n")] = 0;
        char *token;
        char *rest = cmd;
        char *cm1;
        char *cm2 = NULL;
        int cmdCount = 0; // Counter for the number of 'commands'

        // token = strtok_r(rest, " ", &rest);

        // Tokenize the input. The delimiter is set to a space character.
        while ((token = strtok_r(rest, " ", &rest))) {
            // printf("Command %d: %s\n", cmdCount + 1, token); // Print each token
            cmdCount++; // Increment the token (command) counter
            if (cmdCount == 1) {
                cm1 = token;
            }
            else if (cmdCount == 2) {
                cm2 = token;
            }
        }

        // printf("Total number of 'commands': %d\n", cmdCount);

        // Command logic (cd, exit, pwd, lf, lp, and others)
        pid_t pid; // Declared pid for logic reasons

        Command command = getCommand(cm1);
        switch(command) {
            case CMD_EXIT:
                // 'exit' command
                printf("Exiting minishell...\n");
                exit(EXIT_SUCCESS);
                break;
            case CMD_CD:
                // 'cd' command
                if (cmdCount > 2) {
                    fprintf(stderr, "Error: Too many arguments to cd.\n");
                }
                else {
                    execute_cd(cm2);
                }
                break;
            case CMD_PWD:
                // 'pwd' command
                execute_pwd();
                break;
            case CMD_LF:
                // 'lf' command (essentiall a simplier 'ls' command)
                execute_lf();
                break;
            case CMD_SEPT:
                // custom 'sept' command
                // Will add more to this later ;-)
                printf("Do you remember the 21st night of September?");
                break;
            case CMD_UNKNOWN:
            default:
                // This block is executed for commands not built into the shell.
                pid = fork();
                if (pid == -1) {
                    fprintf(stderr, "Error: fork() failed. %s.\n", strerror(errno));
                } else if (pid == 0) {
                    // Child process
                    if (execlp(cm1, cm1, cm2, (char*) NULL) == -1) {
                        fprintf(stderr, "Error: exec() failed. %s.\n", strerror(errno));
                        exit(EXIT_FAILURE);
                        continue;
                    }
                } else {
                    // Parent process
                    int status;
                    if (wait(&status) == -1) {
                        if (errno == EINTR) {
                            // If wait was interrupted by SIGINT. Don't print out an error scenario.
                            continue;
                        }
                        else {
                            fprintf(stderr, "Error: wait() failed. %s.\n", strerror(errno));
                        }
                    }
                }
                break;
        }


    }

    return 0;
}