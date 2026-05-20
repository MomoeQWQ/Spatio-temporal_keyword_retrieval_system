#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <algorithm>
#include <vector>

static PyObject* xor_bytes(PyObject* /*self*/, PyObject* args) {
    Py_buffer a_view;
    Py_buffer b_view;
    if (!PyArg_ParseTuple(args, "y*y*", &a_view, &b_view)) {
        return nullptr;
    }

    const Py_ssize_t out_len = std::min(a_view.len, b_view.len);
    std::vector<unsigned char> out(static_cast<size_t>(std::max<Py_ssize_t>(out_len, 0)));
    for (Py_ssize_t i = 0; i < out_len; ++i) {
        out[static_cast<size_t>(i)] = static_cast<unsigned char>(
            static_cast<unsigned char*>(a_view.buf)[i] ^ static_cast<unsigned char*>(b_view.buf)[i]
        );
    }

    PyObject* result = PyBytes_FromStringAndSize(
        reinterpret_cast<const char*>(out.data()),
        out_len
    );
    PyBuffer_Release(&a_view);
    PyBuffer_Release(&b_view);
    return result;
}

static PyObject* xor_many(PyObject* /*self*/, PyObject* args) {
    PyObject* seq_obj = nullptr;
    if (!PyArg_ParseTuple(args, "O", &seq_obj)) {
        return nullptr;
    }

    PyObject* seq = PySequence_Fast(seq_obj, "expected a sequence of bytes-like objects");
    if (!seq) {
        return nullptr;
    }

    const Py_ssize_t n = PySequence_Fast_GET_SIZE(seq);
    if (n == 0) {
        Py_DECREF(seq);
        return PyBytes_FromStringAndSize("", 0);
    }

    PyObject** items = PySequence_Fast_ITEMS(seq);
    Py_buffer first_view;
    if (PyObject_GetBuffer(items[0], &first_view, PyBUF_SIMPLE) != 0) {
        Py_DECREF(seq);
        return nullptr;
    }

    Py_ssize_t out_len = first_view.len;
    std::vector<unsigned char> out(static_cast<size_t>(std::max<Py_ssize_t>(out_len, 0)));
    for (Py_ssize_t j = 0; j < out_len; ++j) {
        out[static_cast<size_t>(j)] = static_cast<unsigned char*>(first_view.buf)[j];
    }
    PyBuffer_Release(&first_view);

    for (Py_ssize_t i = 1; i < n; ++i) {
        Py_buffer view;
        if (PyObject_GetBuffer(items[i], &view, PyBUF_SIMPLE) != 0) {
            Py_DECREF(seq);
            return nullptr;
        }
        const Py_ssize_t this_len = std::min(out_len, view.len);
        for (Py_ssize_t j = 0; j < this_len; ++j) {
            out[static_cast<size_t>(j)] = static_cast<unsigned char>(
                out[static_cast<size_t>(j)] ^ static_cast<unsigned char*>(view.buf)[j]
            );
        }
        out_len = this_len;
        PyBuffer_Release(&view);
    }

    Py_DECREF(seq);
    return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(out.data()), out_len);
}

static PyObject* xor_pair_lists(PyObject* /*self*/, PyObject* args) {
    PyObject* left_obj = nullptr;
    PyObject* right_obj = nullptr;
    if (!PyArg_ParseTuple(args, "OO", &left_obj, &right_obj)) {
        return nullptr;
    }

    PyObject* left = PySequence_Fast(left_obj, "left must be a sequence");
    if (!left) {
        return nullptr;
    }
    PyObject* right = PySequence_Fast(right_obj, "right must be a sequence");
    if (!right) {
        Py_DECREF(left);
        return nullptr;
    }

    const Py_ssize_t n = std::min(PySequence_Fast_GET_SIZE(left), PySequence_Fast_GET_SIZE(right));
    PyObject* out_list = PyList_New(n);
    if (!out_list) {
        Py_DECREF(left);
        Py_DECREF(right);
        return nullptr;
    }

    PyObject** l_items = PySequence_Fast_ITEMS(left);
    PyObject** r_items = PySequence_Fast_ITEMS(right);
    for (Py_ssize_t i = 0; i < n; ++i) {
        Py_buffer a_view;
        Py_buffer b_view;
        if (PyObject_GetBuffer(l_items[i], &a_view, PyBUF_SIMPLE) != 0) {
            Py_DECREF(left);
            Py_DECREF(right);
            Py_DECREF(out_list);
            return nullptr;
        }
        if (PyObject_GetBuffer(r_items[i], &b_view, PyBUF_SIMPLE) != 0) {
            PyBuffer_Release(&a_view);
            Py_DECREF(left);
            Py_DECREF(right);
            Py_DECREF(out_list);
            return nullptr;
        }

        const Py_ssize_t out_len = std::min(a_view.len, b_view.len);
        std::vector<unsigned char> out(static_cast<size_t>(std::max<Py_ssize_t>(out_len, 0)));
        for (Py_ssize_t j = 0; j < out_len; ++j) {
            out[static_cast<size_t>(j)] = static_cast<unsigned char>(
                static_cast<unsigned char*>(a_view.buf)[j] ^ static_cast<unsigned char*>(b_view.buf)[j]
            );
        }
        PyBuffer_Release(&a_view);
        PyBuffer_Release(&b_view);

        PyObject* item = PyBytes_FromStringAndSize(reinterpret_cast<const char*>(out.data()), out_len);
        if (!item) {
            Py_DECREF(left);
            Py_DECREF(right);
            Py_DECREF(out_list);
            return nullptr;
        }
        PyList_SET_ITEM(out_list, i, item);
    }

    Py_DECREF(left);
    Py_DECREF(right);
    return out_list;
}

static PyMethodDef NativeAccelMethods[] = {
    {"xor_bytes", xor_bytes, METH_VARARGS, "XOR two bytes-like objects."},
    {"xor_many", xor_many, METH_VARARGS, "XOR a sequence of bytes-like objects."},
    {"xor_pair_lists", xor_pair_lists, METH_VARARGS, "Element-wise XOR two sequences of bytes-like objects."},
    {nullptr, nullptr, 0, nullptr}
};

static struct PyModuleDef NativeAccelModule = {
    PyModuleDef_HEAD_INIT,
    "_native_accel",
    "Native acceleration helpers for secure_search.",
    -1,
    NativeAccelMethods
};

PyMODINIT_FUNC PyInit__native_accel(void) {
    return PyModule_Create(&NativeAccelModule);
}
