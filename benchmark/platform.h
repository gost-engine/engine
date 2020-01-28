
#ifdef _MSC_VER
 /** init the clock */
 #define TIMER_INIT \
    LARGE_INTEGER frequency; \
    LARGE_INTEGER t1,t2; \
    double elapsedTime; \
    QueryPerformanceFrequency(&frequency);

 #define TIMER_INIT_EX(CT)	TIMER_INIT
 /** start the performance timer */
 #define TIMER_START QueryPerformanceCounter(&t1);
 /** stop the performance timer and store the result in elapsedTime. */
 #define TIMER_STOP \
    QueryPerformanceCounter(&t2); \
    elapsedTime=(double)(t2.QuadPart-t1.QuadPart)* 1000000 /frequency.QuadPart; 

#else
 #include <sys/time.h>	
 #include <time.h>
	
 #define TIMER_INIT \
  struct timespec ts1, ts2; \
  struct timeval tv1, tv2, delta; \
  double elapsedTime; \
  clockid_t clock_type = CLOCK_MONOTONIC;
  
 #define TIMER_INIT_EX(CT) TIMER_INIT clock_type = CT;  
 #define TIMER_START clock_gettime(clock_type, &ts1); 
 #define TIMER_STOP clock_gettime(clock_type, &ts2);\
			TIMESPEC_TO_TIMEVAL(&tv1, &ts1);\
			TIMESPEC_TO_TIMEVAL(&tv2, &ts2);\
			timersub(&tv2, &tv1, &delta); \
			elapsedTime = (double)delta.tv_sec * 1000000  + (double)delta.tv_usec ;

#endif
