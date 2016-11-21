# Python 3 migration notes for dpkt

This markdown file mainly introduces how to migrate `dpkt` from Python 2 to Python 3 in order to provide support for both the two main versions. Also this doc will also provide some suggestions for future hackers who aim to contribute both Python 2 and 3 compatible code to `dpkt`.

## How to migrate Python 2 code to Python 3

We use the following overall process to migrate `dpkt` from Python 2 to Python 3.

1. Use `2to3` to automatically apply syntax and other obvious changes in Python 3.
2. Run the test cases in migrated module, making sure it could pass all the tests on both Python 2 and 3. If there are problems, go to Step 3, otherwise finish migrating the current module.
3. Manually fix the problems (maybe most of which are caused by string and bytes type change in Python 3).

Based on the overall process, the rest of this section is organised as follows:

First we'll check out what favor `2to3` could do for us. Then we'll dive into details on the manual fix. Since the "bytes and string" problem is a big issue, we'll discuss this tricky issue at the end of this section.

**_1. `2to3` initial conversion_**

`2to3` can automatically solve the following migration issues.

* `int` and `long`

 Python 2 has two integer types `int` and `long`. We may have the code as follows in Python 2.

 ``` python
 tmp = ~crc & 0xffffffffL
 ```

 These have been unified in Python 3, so there is now only one type, `int`. Just get rid of `L`.

  ``` python
 tmp = ~crc & 0xffffffff
  ```

* The Python 2 `print` statement is in Python 3 a function.

 _Python 2_
 ``` python
 print '%s : time = %f kstones = %f' % (function.__name__, time, kstones)
 ```

 _Python 2 & 3_
 ``` python
 print('%s : time = %f kstones = %f' % (function.__name__, time, kstones))
 ```

* In Python 3 the syntax to catch exceptions have changed.

 _Python 2_
 ``` python
 except struct.error, e:
 ```

 _Python 2 & 3_
 ``` python
 except struct.error as e:
 ```
 
* Relative import.

 Python 3 changes the syntax for imports from within a package, requiring you to use the relative import syntax, saying `from . import mymodule` instead of the just `import mymodule`.

* Dictionary methods.
 > In Python 2 dictionaries have the methods `iterkeys()`, `itervalues()` and `iteritems()` that return iterators instead of lists. In Python 3 the standard `keys()`, `values()` and `items()` return dictionary views, which are iterators, so the iterator variants become pointless and are removed.

 Note that `2to3` would replace the old dictionary methods with the new ones in Python 3. If we do not care about the efficiency. Just keep this change and using the new syntax. However, as the Python doc points out:
 > dict.items(): Return a copy of the dictionary’s list of (key, value) pairs.

 > dict.iteritems(): Return an iterator over the dictionary’s (key, value) pairs.
 
 It is recommended to modify the code as follows.
 
 ``` python
 try:
    values = d.itervalues()
 except AttributeError:
    values = d.values()
 ```
 
* `repr()`

 In Python 2 we can generate a string representation of an expression by enclosing it with backticks. However in Python 3 we need to use `repr()` function instead.

* `next` method of the iterator

 In Python 2 iterators have a `.next()` method you use to get the next value from the iterator. For instance,

 ``` python
 >>> i = iter(range(5))
 >>> i.next()
 0
 >>> i.next()
 1
 ```

 This special method has in Python 3 been renamed to `.__next__()` to be consistent with the naming of special attributes elswhere in Python. However, we should generally not call it directly, but instead use the builtin is `next()` function. This function is also available from Python 2.6. Here is an example.

 ``` python
 for _ in range(cnt):
    try:
        ts, pkt = next(iter(self))
 ```

**_2. Manual fix issues_**

* `import` and `dict` related syntax.

 The `import` and `dict` are both changed in Python 3. Note that the `2to3` automatic update cannot provide compatible code for both Python 2 and 3. Thus we should update the code based on different cases. Here are examples.

 _Python 2_
 ``` python
 from StringIO import StringIO
 ```

 _Python 2 & 3_
 ``` python
 try:
    from StringIO import StringIO
 except ImportError:
    from io import StringIO
 ```

* Metaclass related issues

 Based on http://python-3-patterns-idioms-test.readthedocs.org/en/latest/Metaprogramming.html.

 The equivalent of:

 ``` python
 class C: pass
 ```

 is:

 ``` python
 C = type('C', (), {})
 ```

 Thus the metaclass syntax in `dpkt.py` module can be modified, which is both Python 2 and 3 compatible, as follows.

 ``` python
 class Packet(_MetaPacket("Temp", (object,), {}))
 ```
 
* Integer division

 In Python 2, the result of dividing two integers will itself be an integer; in other words 1/2 returns 0. In Python 3 integer division will return an integer only if the result is a whole number. So 1/2 will return 0.5.

 For instance, in `dpkt.py`, the original code is.

 ``` python
 cnt = (n / 2) * 2
 a = array.array('H', buf[:cnt])
 ```

 which would cause the following exception.

 `
 a = array.array('H', buf[:cnt])
 
 TypeError: slice indices must be integers or None or have an __index__ method
 `

 So the code needs to be changed to

 ``` python
 cnt = (n // 2) * 2
 a = array.array('H', buf[:cnt])
 ```

**_3. `bytes` and `str` related issues_**

This is a big issue when migrating `dpkt` to Python 3. The changes between `bytes` and `str` are listed as follows.

> In Python 2, you use `str` objects to hold binary data and ASCII text, while text data that needs more characters than what is available in ASCII is held in `unicode` objects. In Python 3, instead of `str` and `unicode` objects, you use `bytes` objects for binary data and `str` objects for all kinds of text data, Unicode or not. 

When update the original code to support Python 3. We need to keep an eye on the following aspects.

*  string and bytes literals

 If the original Python 2 string is holding byte data, we need to change them be bytes literals by adding a leading `b` to them.

 This occurs dozens of times in the project. We need to inspect carefully which strings are holding byte data and change the type of literals. For instance, in many test cases, we might have statements looks like
 
 ``` python
 ip = IP(id=0, src='\x01\x02\x03\x04', dst='\x01\x02\x03\x04', p=17)
 ```
 
 Defintely we need to add a leading `b` in the two strings, which become
 
 ``` python
 ip = IP(id=0, src=b'\x01\x02\x03\x04', dst=b'\x01\x02\x03\x04', p=17)
 ```
 
* Change `str()` to `bytes()` where necessary
 
 It is common case when we use `dpkt` to convert a protocol object, e.g. IP, TCP, etc., to string form. Such as

 ``` python
 assert (str(ip) == s)
 ```
 
 At this time, it is essential to change the code as follows
 
 ``` python
 assert (bytes(ip) == s)
 ```
 
 As a consequence, this change leads to the next key point - `__str__` and `__bytes__` function update.
 
* `__str__` and `__bytes__` function
 
 As aforementioned `str()` to `bytes()` update. We have to change the implementation of `__str__` and `__bytes__` respectively. Most of `dpkt` modules do not have a `__bytes__` yet, because in Pythnon 2, its funcionality is exactly the same as `__str__`. However in Python 3, things become different. In my experience, in most situations `dpkt` is dealing with `bytes` data. Thus it is important to provide `__bytes__` implementation for every needed class.

 For instance, the origin `__str__` fuction of `IP` class is
 
 ``` python
 def __str__(self):
        self.len = self.__len__()
        if self.sum == 0:
            self.sum = dpkt.in_cksum(self.pack_hdr() + str(self.opts))
            if (self.p == 6 or self.p == 17) and (self.off & (IP_MF | IP_OFFMASK)) == 0 and \
                    isinstance(self.data, dpkt.Packet) and self.data.sum == 0:
                # Set zeroed TCP and UDP checksums for non-fragments.
                p = str(self.data)
                s = dpkt.struct.pack('>4s4sxBH', self.src, self.dst,
                                     self.p, len(p))
                s = dpkt.in_cksum_add(0, s)
                s = dpkt.in_cksum_add(s, p)
                self.data.sum = dpkt.in_cksum_done(s)
                if self.p == 17 and self.data.sum == 0:
                    self.data.sum = 0xffff  # RFC 768
                    # XXX - skip transports which don't need the pseudoheader
        return self.pack_hdr() + str(self.opts) + str(self.data)
 ```
 
 Now we modify the `__str__` and add `__bytes__` function as follows.
 
 ``` python
 def __str__(self):
        return str(self.__bytes__())
    
 def __bytes__(self):
        self.len = self.__len__()
        if self.sum == 0:
            self.sum = dpkt.in_cksum(self.pack_hdr() + bytes(self.opts))
            if (self.p == 6 or self.p == 17) and (self.off & (IP_MF | IP_OFFMASK)) == 0 and \
                    isinstance(self.data, dpkt.Packet) and self.data.sum == 0:
                # Set zeroed TCP and UDP checksums for non-fragments.
                p = bytes(self.data)
                s = dpkt.struct.pack('>4s4sxBH', self.src, self.dst,
                                     self.p, len(p))
                s = dpkt.in_cksum_add(0, s)
                s = dpkt.in_cksum_add(s, p)
                self.data.sum = dpkt.in_cksum_done(s)
                if self.p == 17 and self.data.sum == 0:
                    self.data.sum = 0xffff  # RFC 768
                    # XXX - skip transports which don't need the pseudoheader
        return self.pack_hdr() + bytes(self.opts) + bytes(self.data)
 ```
 
 Please carefully check the differences between to get a perceptual understanding of how to update `__bytes__` and `__str__`.

* `chr` and `ord` built-in function

 For `ord(c)`, given a string of length one, it'll return an integer representing the Unicode code point of the character when the argument is a unicode object, or the value of the byte when the argument is an 8-bit string. While for `chr(i)`, it'll return a string of one character whose ASCII code is the integer i.

 In Python 2, both of the two function's usage is straight forward. For example, we have the following code snippet.

 ``` python
 l = buf.split(chr(IAC))
 ```

 However, in Python 3, please note that most time in `dpkt` we'll deal with data with the type of `bytes`. Thus it is improper if the `buf` is of the type of `bytes` while the `chr()` function returns `str`. In order to solve this problem, we update the code as follows to provide support for both Python 2 and 3.

 ``` python
 if sys.version_info < (3,):
    l = buf.split(chr(IAC))
 else:
    l = buf.split(struct.pack("B", IAC))
 ```

 Similarly, for `ord` function, we could have the snippet as follows,

 ``` python
 o = ord(w[0])
 ```

 where `w` is a string and `o` is an integer. Yet in Python 3, every element of `bytes` array is an integer, thus it is no need for the calling of `ord` any more. 

 Due to the expandability consideration, we add a `compatible` module in the project, and it'll provide some functions that are both compatible for Python 2 and 3. Currently there is only one function, namely, `ord`. Please see the implementation below.

 ``` python
 if sys.version_info < (3,):
    def compatible_ord(char):
        return ord(char)
 else:
    def compatible_ord(char):
        return char
 ```

 Using the `compatible` module, the contributor only need to modify the client code as follows.

 ``` python
 o = compatible.compatible_ord(w[0])
 ```

## How to contribute both Python 2 and 3 compatible code

If you want to contribute new code to `dpkt`, it is essential to write both Python 2 and 3 compatible code. After `dpkt 2.0`, we'll both provide Python 2.6+ and 3.x support. Also the auto build system `travis` will build on both 2 and 3 for every PR and commit.

Well, my suggestions for writing both Python 2 and 3 compatible code are as follows.

1. Read the `How to migrate Python 2 code to Python 3` section of this documentation and get familar with the key issues while migration the project to Python 3.
2. Setup both 2 and 3 environments on your local machine.
3. Follow the rules below to contribute new code. http://python-future.org/compatible_idioms.html
