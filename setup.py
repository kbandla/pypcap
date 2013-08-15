from distutils.core import setup, Extension

setup(
    name = "pypcap",
    author = "Kiran Bandla",
    author_email = "kbandla@in2void.com",
    license = "BSD",
    version = '0.1',
    description = "Python bindings for the libpcap library",
    long_description = "Python/C Wrapper for the libpcap library",
    url = "http://www.github.com/kbandla/pypcap",
    ext_modules = [Extension(
        "pypcap",
        sources = ["pypcap.c"],
        libraries = ["pcap"],
        ) ],
)
