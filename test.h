#ifndef TEST_H
#define TEST_H



#define T(e) do{ if (!(e)) { ERR_print_errors_fp(stderr); OpenSSLDie(__FILE__, __LINE__, #e); } }while (0)

#define TE(e) do{ if (!(e)) { \
                ERR_print_errors_fp(stderr); \
                fprintf(stderr, "Error at %s:%d %s\n", __FILE__, __LINE__, #e); \
                return -1; } }while (0) 

#define TEST_ASSERT(e) do{ test = (e);}while (0); if (test) \
           printf(cRED "  Test FAILED\n" cNORM); \
        else \
           printf(cGREEN "  Test passed\n" cNORM)\
             

#ifdef __GNUC__
# define _UNUSED_ __attribute__ ((unused))
#else
# define _UNUSED_
#endif

_UNUSED_ static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
    int n = 0;

    if(title!=NULL) fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0)
            fprintf(f, "\n%04x", n);
        fprintf(f, " %02x", s[n]);
    }
    fprintf(f, "\n");
}

_UNUSED_ static void hexdump_inline(const void *ptr, size_t len) 
{
    const unsigned char *p = ptr;
    size_t i, j;

    for (i = 0; i < len; i += j) {
    for (j = 0; j < 16 && i + j < len; j++)
        printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n");
}



#ifdef _WIN32
 #include <stdlib.h>
 static inline int setenv(const char* name, const char* value,int overwrite){
    return _putenv_s(name, value);
 }
#else
 #include <unistd.h>
 #include <arpa/inet.h>
#endif

#endif       


