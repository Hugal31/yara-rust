#include "yara.h"

#if !defined (YR_MAJOR_VERSION) || !defined (YR_MINOR_VERSION)
# error "Yara version macro not defined."
#endif

#if YR_MAJOR_VERSION != 4
# if YR_MAJOR_VERSION < 4
#  error "Only Yara v4 is supported."
# else
#  warning "Yara versons above v4 are not supported. Please use Yara v4."
# endif
#endif
