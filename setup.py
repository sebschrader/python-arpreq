from setuptools import Extension, find_packages, setup

arpreq = Extension('arpreq', sources=['arpreq/arpreq.c'],
                   extra_compile_args=['-std=c99'])

setup(name='arpreq',
      author='Sebastian Schrader',
      author_email='sebastian.schrader@ossmail.de',
      url='https://github.com/sebschrader/python-arpreq',
      version='0.1.0',
      description="Query the Kernel ARP cache for the MAC address "
                  "corresponding to IP address",
      packages=find_packages(exclude=["*.tests"]),
      ext_modules=[arpreq],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: MIT License',
          'Intended Audience :: System Administrators',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: Implementation :: CPython',
          'Topic :: System :: Networking',
      ],
      )
