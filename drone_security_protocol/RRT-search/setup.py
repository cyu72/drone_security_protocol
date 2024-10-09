from setuptools import setup, Extension
from Cython.Build import cythonize

ext_modules = [
    Extension(
        "drone_wrapper",
        sources=[
            "/app/drone_security_protocol/RRT-search/drone_wrapper.pyx",
        ],
        include_dirs=[
            "/app/drone_security_protocol/include",
            "/app/drone_security_protocol/include/routing",
            "/app/drone_security_protocol/include/routing/network_adapters"
            "/app/drone_security_protocol/build/_deps/nlohmann_json-src/include",
        ],
        language="c++",
        extra_compile_args=["-std=c++17"],
        libraries=["ssl", "crypto", "drone"],
        library_dirs=["/app/drone_security_protocol/build"],
    )
]

setup(
    name="drone_wrapper",
    ext_modules=cythonize(ext_modules, language_level="3"),
)