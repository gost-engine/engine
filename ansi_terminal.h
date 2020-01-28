/* adopted from https://github.com/sol-prog/ansi-escape-codes-windows-posix-terminals-c-programming-examples */

#define cRED    "\033[1;31m"
#define cDRED   "\033[0;31m"
#define cGREEN  "\033[1;32m"
#define cDGREEN "\033[0;32m"
#define cBLUE   "\033[1;34m"
#define cDBLUE  "\033[0;34m"
#define cNORM   "\033[m"

void setupConsole(void);
void restoreConsole(void);
void getCursorPosition(int *row, int *col);
