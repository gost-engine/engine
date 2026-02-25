#pragma once

#include <stdbool.h>

#define MEMBER_SUFFIX _private
#define MEMBER_SUFFIX_ISSET _private_isset

#define DETAILS_BASE_NAME base

#define DETAILS_MAKE_NAME_IMPL(prefix, suffix) prefix##suffix
#define DETAILS_MAKE_NAME(prefix, suffix) DETAILS_MAKE_NAME_IMPL(prefix, suffix)

#define DETAILS_MEMBER_NAME(name) DETAILS_MAKE_NAME(name, MEMBER_SUFFIX)
#define DETAILS_MEMBER_NAME_ISSET(name) DETAILS_MAKE_NAME(name, MEMBER_SUFFIX_ISSET)

#define DETAILS_GET_BASE_MEMBER(object, name) ( \
    ((object)->DETAILS_MEMBER_NAME(DETAILS_BASE_NAME)) ? \
    	((object)->DETAILS_MEMBER_NAME(DETAILS_BASE_NAME)->DETAILS_MEMBER_NAME(name)) : \
    	0 \
)

#define DETAILS_GET_MEMBER(object, name) ( \
    ((object)->DETAILS_MEMBER_NAME_ISSET(name)) ? \
    	((object)->DETAILS_MEMBER_NAME(name)) : \
    	DETAILS_GET_BASE_MEMBER(object, name) \
)

#define DECL_MEMBER(type, name) \
	type DETAILS_MEMBER_NAME(name); \
	bool DETAILS_MEMBER_NAME_ISSET(name)

#define DECL_BASE(type) DECL_MEMBER(type*, DETAILS_BASE_NAME)

#define INIT_MEMBER(name, val) \
	.DETAILS_MEMBER_NAME(name) = (val), \
	.DETAILS_MEMBER_NAME_ISSET(name) = true

#define GET_MEMBER(object, name) DETAILS_GET_MEMBER(object, name)
