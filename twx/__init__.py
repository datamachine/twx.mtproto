import sys

"""
Extend the twx namespace
"""
if sys.version_info > (3, 1, 0):
    from pkgutil import extend_path
    __path__ = extend_path(__path__, __name__)
