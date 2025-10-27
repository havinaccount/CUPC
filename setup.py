try:
    import multiprocessing
    import os

    from setuptools import setup
    from setuptools.command.install import install
except ModuleNotFoundError as e:
    print(f"One of the modules have not been found: {e}")
    raise
except ImportError as e:
    print(f"Something happened while trying to import modules: {e}")
    raise
"""
Setup file for CUPC, Please change the modules as CUPC update (If not updated.)
"""


class BuildWithNuitka(install):
    def run(self):
        os.system(
            f"nuitka --lto=yes --onefile --follow-imports --output-dir=dist --remove-output --jobs={multiprocessing.cpu_count} cupc.py"
        )
        install.run(self)


setup(
    name="CUPC",
    version="1.0.4",
    author="havinacoount",
    description="""Constant Username and Password Checker (CUPC)
    is an simple project that tries to replicate a simple Login portal
    trying to have as least as possible flaws. D o  n o t  u s e  i t  o n  a n y  p r o j e c t  t h a t  i s  c r i t i c a l
    """,
    py_modules=["cupc"],
    install_requires=[
        "bcrypt",
        "orjson",
        "getpass4",
        "blake3",
        "numpy",
        "colorama",
    ],
    entry_points={"console_scripts": ["cupc=cupc:main"]},
    python_requires=">=3.10",
    cmdclass={"install": BuildWithNuitka},
)
