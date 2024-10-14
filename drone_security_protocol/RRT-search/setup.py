from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy as np

ext_modules = [
    Extension(
        "drone_wrapper",
        sources=[
            "/app/drone_security_protocol/RRT-search/drone_wrapper.pyx",
        ],
        include_dirs=[
            "/app/drone_security_protocol/include",
            "/app/drone_security_protocol/include/routing",
            "/app/drone_security_protocol/include/routing/network_adapters",
            "/app/drone_security_protocol/build/_deps/nlohmann_json-src/include",
        ],
        language="c++",
        extra_compile_args=["-std=c++17"],
        libraries=["ssl", "crypto", "drone"],
        library_dirs=["/app/drone_security_protocol/build"],
    ),
    Extension(
        "rrt",
        sources=[
            "/app/drone_security_protocol/RRT-search/rrt.pyx",
        ],
        include_dirs=[np.get_include()],
        extra_compile_args=["-fopenmp"],
        extra_link_args=["-fopenmp"],
    ),
]

setup(
    name="drone_modules",
    ext_modules=cythonize(ext_modules, compiler_directives={
        'language_level': "3",
        'boundscheck': False,
        'wraparound': False,
        'nonecheck': False,
        'cdivision': True,
    }),
    include_dirs=[np.get_include()],
    zip_safe=False,
)