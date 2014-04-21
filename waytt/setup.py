import os
from distutils.core import setup, Extension

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='WAYTT',
      version='0.1',
      author = "othrayte",
      author_email = "othrayte@gmail.com",
      description = "Who Are You Talking To?, a python c module for measuring network traffic by destination and source.",
      license = "GPLv3+",
      keywords = "network traffic monitor measure",
      url = "https://github.com/othrayte/waytt",
      long_description=read('README'),
      classifiers=[
          "Development Status :: 3 - Alpha",
          "Topic :: Utilities",
          "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
          "Programming Language :: C++",
          "Programming Language :: Python :: 3",
          "Topic :: Software Development :: Libraries :: Python Modules",
          "Topic :: Internet",
          "Topic :: System :: Monitoring",
          "Topic :: System :: Networking :: Monitoring",
      ],
      ext_modules=[Extension('waytt',
                             ['wayttmodule.cpp'],
                             include_dirs=['include'],
                             library_dirs=['lib'])],
                             libraries=[('wpcap',{'sources': []})])