from setuptools import setup
import sys

revision = None

# must match PEP 440
_MAJOR_VERSION         = 0
_MINOR_VERSION         = 0
_MICRO_VERSION         = 1
_PRE_RELEASE_TYPE      = 'a'   # a | b | rc
_PRE_RELEASE_VERSION   = 1
_DEV_RELEASE_VERSION   = 1

version = '{}.{}'.format(_MAJOR_VERSION, _MINOR_VERSION)
revision = None

if _MICRO_VERSION is not None:
    version += '.{}'.format(_MICRO_VERSION)

if _PRE_RELEASE_TYPE is not None and _PRE_RELEASE_VERSION is not None:
    version += '{}{}'.format(_PRE_RELEASE_TYPE, _PRE_RELEASE_VERSION)

if _DEV_RELEASE_VERSION is not None:
    version += '.dev{}'.format(_DEV_RELEASE_VERSION)
    revision = 'master'
else:
    revision = version
    
download_url = 'https://github.com/datamachine/twx/archive/{}.tar.gz'.format(revision)

print(version)
print(download_url)

development_status=[
    "",
    "Development Status :: 1 - Planning",
    "Development Status :: 2 - Pre-Alpha",
    "Development Status :: 3 - Alpha",
    "Development Status :: 4 - Beta",
    "Development Status :: 5 - Production/Stable",
    "Development Status :: 6 - Mature",
    "Development Status :: 7 - Inactive"
]

setup(
    name = 'twx.mtproto',
    packages = ['twx', 'twx.mtproto'],
    version = version,
    description = "Unofficial Telegram MTProto Client",
    long_description = open("README.rst").read(),
    author = 'Vince Castellano, Phillip Lopo',
    author_email = 'surye80@gmail.com, philliplopo@gmail.com',
    keywords = ['datamachine', 'telex', 'telegram', 'bot', 'mtproto'],
    url = 'https://github.com/datamachine/twx', 
    download_url = download_url, 
    install_requires=['requests'],
    platforms = ['Linux', 'Unix', 'MacOsX', 'Windows'],
    classifiers = [
      development_status[1],
      'Intended Audience :: Developers',
      'License :: OSI Approved :: MIT License',
      'Operating System :: OS Independent',
      'Programming Language :: Python :: 3 :: Only',
      'Programming Language :: Python :: 3.4',
      'Topic :: Communications :: Chat',
      'Topic :: Communications :: File Sharing'
      ]
)
