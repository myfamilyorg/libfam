#include <libfam/utils.h>

i32 __err_value = 0;
PUBLIC i32 *__error(void) { return &__err_value; }
i32 *__err_location(void) { return &__err_value; }

