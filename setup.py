from setuptools import setup, find_packages
import os


base_dir = os.path.dirname(__file__)
__author__ = "Kay Hau"
__email__ = "virtualda@gmail.com"
__title__ = "cognitoauth"
__version__ = "0.1.0"
__summary__ = "This package creates a framework for python packages to be built."
__uri__ = "https://github.com/kyhau/aws-cognito-token-verification-serverside"

__requirements__ = [
    "six>=1.10.0",
    "pytz==2022.6",
    "python-jose==3.3.0",
    "requests[security]"
]

__long_description__ = ""
try:
    # Reformat description as PyPi use ReStructuredText rather than Markdown
    import m2r

    __long_description__ = m2r.parse_from_file(os.path.join(base_dir, "README.md"))
except (ImportError, IOError, OSError) as e:
    import logging

    logging.warning(f"m2r conversion failed: {e}")

CLASSIFIERS = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3 :: Only",
]

setup(
    author=__author__,
    author_email=__email__,
    classifiers=CLASSIFIERS,
    # data_files parameter is only required for files outside the packages, used in conjunction with the MANIFEST.in
    data_files=[("", ["ReleaseNotes.md"]),],
    description=__summary__,
    install_requires=__requirements__,
    long_description=__long_description__,
    name=__title__,
    # For data inside packages can use the automatic inclusion
    #   include_package_data = True,
    # or the explicit inclusion, e.g.:
    #   package_data={ "package_name": ["data.file1", "data.file2" , ...] }
    packages=find_packages(exclude=["tests"]),
    url=__uri__,
    version=__version__,
    zip_safe=False,
)
