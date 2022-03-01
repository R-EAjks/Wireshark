#ifndef __BB_NR5G_INSTR_MACROS_H__INCLUDED__
#define __BB_NR5G_INSTR_MACROS_H__INCLUDED__

#ifdef PREFIX
#undef PREFIX
#endif
#ifdef VFIELD
#undef VFIELD
#endif
#ifdef AFIELD
#undef AFIELD
#endif

/* macro to define fields for both "internal" C source code use and public interface use.
 * If compiled with bb_nr5g_INTERNAL defined, the .h generate structs with pointer and
 * pointer array directly usable in source code.
 * In case bb_nr5g_INTERNAL is not defined the .h generate a pseudo-code interface suitable for
 * public use (no pointer nor array pointer) with optional fields and variable arrays. */
#ifdef bb_nr5g_INTERNAL
#  define PREFIX(name__) tm_ ## name__
#  define VFIELD(type__, name__) type__ *name__
#  define AFIELD(type__, name__, size__) type__ *name__ [(size__)]
#else
#  define PREFIX(name__) name__
#  define VFIELD(type__, name__) type__ name__
#  define AFIELD(type__, name__, size__) type__ name__ [0]
#endif

#endif /* __BB_NR5G_INSTR_MACROS_H__INCLUDED__ */
