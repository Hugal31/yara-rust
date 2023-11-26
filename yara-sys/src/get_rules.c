#include "yara.h"
#include "yara/rules.h"

size_t get_rules(YR_RULES *ruleset, YR_RULE *rules[], size_t n) {
	YR_RULE* rule;
	size_t i = 0;
	yr_rules_foreach(ruleset, rule) {
		if (i < n)
		{
		    rules[i] = rule;
		    i++;
		}
	}
	return i;
}

size_t get_num_rules(YR_RULES *ruleset) {
    YR_RULE* rule;
    size_t n = 0;
    yr_rules_foreach(ruleset, rule) {
        n++;
    }
    return n;
}
