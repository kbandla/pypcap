import os
from distutils.core import setup, Extension

def get_version():
    with open(os.path.join(os.path.dirname(__file__), 'pypcap.c'),'r') as f:
        for line in f:
            if "#define PYPCAP_VERSION" in line:
                return line.split()[-1].strip('"')

setup(
    name = "pypcap",
    author = "Kiran Bandla",
    author_email = "kbandla@in2void.com",
    license = "BSD",
    version = get_version(),
    description = "Python bindings for the libpcap library",
    long_description = "Python/C Wrapper for the libpcap library",
    url = "http://www.github.com/kbandla/pypcap",
    ext_modules = [Extension(
        "pypcap",
        sources = ["pypcap.c"],
        libraries = ["pcap"],
        ) ],
)
