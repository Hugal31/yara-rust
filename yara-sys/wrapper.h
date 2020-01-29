#include "yara.h"

#if !defined (YR_MAJOR_VERSION) || !defined (YR_MINOR_VERSION)
# error Yara version macro not defined.
#endif

#if YR_MAJOR_VERSION == 3 && YR_MINOR_VERSION <= 7
typedef struct _YR_MATCH YR_MATCH;
#endif
