```
/* Bytecode object */
typedef struct {
    PyObject_HEAD
    int co_argcount;            /* #arguments, except *args */
    int co_nlocals;             /* #local variables */
    int co_stacksize;           /* #entries needed for evaluation stack */
    int co_flags;               /* CO_..., see below */
    PyObject *co_code;          /* instruction opcodes */
    PyObject *co_consts;        /* list (constants used) */
    PyObject *co_names;         /* list of strings (names used) */
    PyObject *co_varnames;      /* tuple of strings (local variable names) */
    PyObject *co_freevars;      /* tuple of strings (free variable names) */
    PyObject *co_cellvars;      /* tuple of strings (cell variable names) */
    /* The rest doesn't count for hash/cmp */
    PyObject *co_filename;      /* string (where it was loaded from) */
    PyObject *co_name;          /* string (name, for reference) */
    int co_firstlineno;         /* first source line number */
    PyObject *co_lnotab;        /* string (encoding addr<->lineno mapping) */
    void *co_zombieframe;       /* for optimization only (see frameobject.c) */
} PyCodeObject;
 
 
co_argcount ：   Code Block的位置参数个数，比如说一个函数的位置参数个数
co_nlocals：     Code Block中局部变量的个数，包括其中位置参数的个数
co_stacksize：   执行该段Code Block需要的栈空间
co_flags：       N/A
co_code：        Code Block编译所得的字节码指令序列。以PyStingObjet的形式存在
co_consts：      PyTupleObject对象，保存CodeBlock中的所常量
co_names：       PyTupleObject对象，保存CodeBlock中的所有符号
co_varnames：    Code Block中的局部变量名集合
co_freevars：    Python实现闭包需要用的东西
co_cellvars：    Code Block中内部嵌套函数所引用的局部变量名集合
co_filename：    Code Block所对应的.py文件的完整路径
co_name：        Code Block的名字，通常是函数名或类名
co_firstlineno： Code Block在对应的.py文件中起始行
co_lnotab：      字节码指令与.py文件中source code行号的对应关系，以PyStringObject的形式存在
```