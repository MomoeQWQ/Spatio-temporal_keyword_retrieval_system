"""Build optional C++ native acceleration for secure_search."""

from __future__ import annotations

from setuptools import Extension, setup


ext_modules = [
    Extension(
        "core.secure_search._native_accel",
        sources=["core/secure_search/_native_accel.cpp"],
        language="c++",
        extra_compile_args=["-O3"],
        extra_link_args=["-static-libgcc", "-static-libstdc++"],
    )
]


setup(
    name="secure_search_native_accel",
    version="0.1.0",
    description="Optional native acceleration for secure_search XOR hot paths",
    ext_modules=ext_modules,
)
