#ifndef _WCJSLOGGING_H_
#define _WCJSLOGGING_H_

#ifdef CONFIG_DEBUG
#include <stdlib.h>
#include <stdio.h>

#define XLOG(...)   fprintf(stdout, __VA_ARGS__)

#define LL()    do { XLOG("#%s:%d\n", __FILE__, __LINE__ );   } while(0)

#define FATAL(...) do { \
    if( __VA_ARGS__ ) {\
        XLOG("[FATAL]  %s:%d\n", __FILE__, __LINE__ ); \
        exit(0); \
    }\
} while(0);


#define ERR(lbl) do {  LL(); goto lbl; } while(0);


#else

#define XLOG(...)   ;
#define LL()    ;

#define FATAL(...) do { \
    if( __VA_ARGS__ ) {\
        exit(__LINE__); \
    }\
} while(0);

#endif /* CONFIG_DEBUG */

#endif /* _WCJSLOGGING_H_ */
