# Overview

Libfam comes with formatting/printing utilities that are meant to be used in the place of printf and other stdandard library tools. The design includes The Formatter struct which has the format_append, format_clear and format_to_stirng functions. These allow for building formatted strings iteratively. Next we have the FORMAT macro which can be used to format text. Finally, we have the println/print/panic macros which can output text to the screen (updated printf functions). The macros automiatcally detect the type using the "_Generic" macro capabilities in C. This includes the integer types, floating point types, strings, and addresses.


# Examples

FORMAT:

```
Formatter f = FORMATTER_INIT;
FORMAT(&f, "a={},b={}", 1, 2);
FORMAT(&f, ",c={},d={}", 3, 4);
const u8 *s = format_to_string(&f);
write(2, s, strlen(s));
```

Or, FORMAT can be used indirectly by using the println/print/panic macros:

```
println("a={},b={},c={},d={},s={}", 1, 2, 3, 4, "string");
```

print is just like println, but without a newline and panic is like println, but exits after printing is complete.

All of these macros support several display options. For instance {c} - char, {b} - binary, {x} - lower case hex, {X} upper case hex and {n} for comma formatting.

For example:

```
println("a={c},b={b},c={x},d={X},e={n}", 'a', 3, 0xFF, 0xFF, 1234567);
```

Would print out:

```
a=a,b=11,c=0xff,d=0xFF,e=1,234,567
```

For floating point numbers, precision can be specified with the '.' symbol.

```
println("x={.4}", 1.23456789);
```

The output of this is:

```
x=1.2345
```

In addition, {:NNN}, {:<NNN}, and {:>NNN} can be used for alignment of text.
```
println("a={:10},b={:<5},c={:>5}", 1, 1, 1);
```

The output of this is:

```
a=          1,b=1    ,c=    1
```

Finally, the '{{' and '}}' symbols can used to display a single '{' and '}' respectively:

```
println("v={{,w=}} {}", "test");
```

The output is:

```
v={,w=} test
```

# Architecture/Design

At its core all the functions use the Formatter type and the functions that are defined for it. They progressively reallocate the buffer as needed. Based on this core functionality we extend formatting in a number of different directions (print, println, panic, ASSERT, ASSERT_EQ). We iterate efficiently through using an aho corasick-like algorithm for efficient matching. This allows for functionality similar to StringBuilder in java with the formatting syntax similar to Rust.
