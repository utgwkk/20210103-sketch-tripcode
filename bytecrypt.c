#define _GNU_SOURCE
#include <crypt.h>
#include <Python.h>

/* ref:
 * - https://github.com/python/cpython/blob/f7f0ed59bcc41ed20674d4b2aa443d3b79e725f4/Modules/_cryptmodule.c
 * - https://github.com/python/cpython/blob/f7f0ed59bcc41ed20674d4b2aa443d3b79e725f4/Modules/clinic/_cryptmodule.c.h
 */
static PyObject* bytecrypt (PyObject *module, PyObject *const *args, Py_ssize_t nargs) {
    PyObject *return_value = NULL;
    const char *word, *salt, *crypted;
    struct crypt_data data;

    word = PyBytes_AsString(args[0]);
    if (word == NULL) {
        goto exit;
    }
    salt = PyBytes_AsString(args[1]);
    if (salt == NULL) {
        goto exit;
    }

    memset(&data, 0, sizeof(data));
    crypted = crypt_r(word, salt, &data);
    if (crypted == NULL) {
        return_value = PyErr_SetFromErrno(PyExc_OSError);
        goto exit;
    }

    return_value = PyBytes_FromString(crypted);

exit:
    return return_value;
}

static PyMethodDef ByteCryptMethods[] = {
    {"crypt", (PyCFunction)bytecrypt, METH_FASTCALL, "Same as crypt.crypt() but takes two bytes"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef bytecryptmodule = {
    PyModuleDef_HEAD_INIT,
    "bytecrypt",
    NULL,
    -1,
    ByteCryptMethods,
};

PyMODINIT_FUNC PyInit_bytecrypt (void) {
    return PyModule_Create(&bytecryptmodule);
}
